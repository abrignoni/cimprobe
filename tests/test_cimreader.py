"""Tests for the WMI CIM repository reader.

The fixtures are synthetic repositories built by a small writer that lives only in this
file. It lays out mapping files, index pages, data pages, class definitions and
instances from python-cim's structure definitions (and, where cimreader departs from
python-cim, from what known data showed), and the reader is required to hand back
exactly the namespaces, classes and property values that went in.

That proves the reader against a second reading of the same description, which is
worth having and is not the same as proving it against evidence. The evidence proof is
the known-data comparison described in the README: a repository Windows itself wrote,
checked property by property against Get-CimInstance.
"""

import hashlib
import io
import json
import os
import struct
import sys
from contextlib import redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cimreader  # noqa: E402

PAGE = cimreader.DATA_PAGE_SIZE

T_STRING, T_BOOL, T_UINT8, T_UINT32, T_REF, T_SINT16 = 0x08, 0x0B, 0x11, 0x13, 0x66, 0x02

# --------------------------------------------------------------- the writer


def wstr(s):
    """A data-region string: byte 0 then Latin-1, or byte 1 then UTF-16LE."""
    try:
        return b"\x00" + s.encode("latin-1") + b"\x00"
    except UnicodeEncodeError:
        return b"\x01" + s.encode("utf-16-le") + b"\x00\x00"


class Region(object):
    def __init__(self):
        self.buf = bytearray()

    def add(self, b):
        off = len(self.buf)
        self.buf += b
        return off

    def string(self, s):
        return self.add(wstr(s))


def slot(t, v):
    return struct.pack(cimreader._VALUE_FORMATS[t], v)


def qualifiers(entries):
    body = b"".join(entries)
    return struct.pack("<I", 4 + len(body)) + body


KEY_QUALIFIER = struct.pack("<IB4BH", 0x80000001, 0, T_BOOL, 0, 0, 0, 0xFFFF)


class Prop(object):
    def __init__(self, name, t, array=False, key=False, default=None):
        self.name, self.t, self.array, self.key, self.default = name, t, array, key, default

    def type_bytes(self):
        return bytes([self.t, 0x20 if self.array else 0, 0, 0])

    def width(self):
        return 4 if self.array else struct.calcsize(cimreader._VALUE_FORMATS[self.t])


class Cls(object):
    def __init__(self, name, super_=None, props=(), ts=0x01D0000000000000):
        self.name, self.super, self.own, self.ts = name, super_, list(props), ts


def layout(classes, name):
    chain = []
    c = classes[name]
    while c:
        chain.append(c)
        c = classes.get(c.super) if c.super else None
    chain.reverse()
    props = [p for c in chain for p in c.own]
    return chain, props


def states(bits):
    out = bytearray((2 * len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        out[i // 4] |= b << (2 * (i % 4))
    return bytes(out)


def class_definition(classes, name):
    c = classes[name]
    chain, props = layout(classes, name)
    reg = Region()
    name_off = reg.string(c.name)
    refs = []
    base = len(props) - len(c.own)
    for i, p in enumerate(c.own):
        pn = reg.string(p.name)
        q = qualifiers([KEY_QUALIFIER] if p.key else [])
        ps = reg.add(p.type_bytes() + struct.pack("<HII", base + i, 0, len(chain) - 1) + q)
        refs.append((pn, ps))
    # default values: two state bits and one slot per property of the full layout
    bits, slots = [], b""
    for i, p in enumerate(props):
        own = i >= base
        if p.default is None:
            bits.append(0b01 if own else 0b11)
            slots += b"\x00" * p.width()
        elif own:
            bits.append(0b00)
            slots += slot(p.t, p.default)
        else:
            bits.append(0b10)                      # inherited, with a default an ancestor holds
            slots += b"\x00" * p.width()
    pdv = states(bits) + slots
    sup = c.super or ""
    head = struct.pack("<I", len(sup)) + sup.encode("utf-16-le")
    head += struct.pack("<QIBIII", c.ts, 0, 0, name_off, len(pdv), 4 if not sup else len(sup) + 8)
    if sup:
        head += b"\x00" + sup.encode("ascii") + b"\x00" + struct.pack("<I", len(sup))
    body = qualifiers([])
    body += struct.pack("<I", len(refs)) + b"".join(struct.pack("<II", a, b) for a, b in refs)
    body += pdv
    body += struct.pack("<I", 0x80000000 | len(reg.buf)) + bytes(reg.buf)
    body += struct.pack("<I", 12) + b"\x00" * 8            # the method part, its size counting itself
    return head + body


NULL = object()
DEFAULT = object()


def instance(classes, name, values, hash_chars, ts1=0x01DC000000000001, ts2=0x01DC000000000002, dynprops=1):
    chain, props = layout(classes, name)
    reg = Region()
    reg.string(name)
    bits, slots = [], b""
    for p in props:
        v = values.get(p.name, NULL)
        if v is NULL:
            bits.append(0b01)
            slots += b"\x00" * p.width()
        elif v is DEFAULT:
            bits.append(0b10)
            slots += b"\x00" * p.width()
        else:
            bits.append(0b00)
            if p.array:
                ref = reg.add(struct.pack("<I", len(v)) + b"".join(slot(p.t, x) for x in v))
                slots += struct.pack("<I", ref)
            elif p.t in (T_STRING, T_REF):
                slots += struct.pack("<I", reg.string(v))
            elif p.t == T_BOOL:
                slots += struct.pack("<H", 0xFFFF if v else 0)
            else:
                slots += slot(p.t, v)
    out = ("A" * hash_chars).encode("utf-16-le")
    out += struct.pack("<QQIIB", ts1, ts2, 0, 0, 0) + states(bits) + slots + qualifiers([])
    out += bytes([dynprops]) + struct.pack("<I", len(reg.buf)) + bytes(reg.buf)
    return out


def index_page(keys, children, sig=cimreader.PAGE_TYPE_ACTIVE, root_page=0, logical=0):
    data = bytearray()
    offsets = []
    sdt = []
    refs = []
    for k in keys:
        parts = k.split("/")
        refs.append(len(sdt))
        sdt.append(len(parts))
        for part in parts:
            sdt.append(len(offsets))
            offsets.append(len(data))
            data += part.encode("ascii") + b"\x00"
    if not offsets:
        offsets = [0]            # the string table always holds one more offset than its length field
    n = len(keys)
    buf = struct.pack("<5I", sig, logical, 0, root_page, n)
    buf += b"\x00" * (4 * n)
    buf += struct.pack("<%dI" % (n + 1), *children)
    buf += struct.pack("<%dH" % n, *refs)
    buf += struct.pack("<H", len(sdt)) + struct.pack("<%dH" % len(sdt), *sdt)
    buf += struct.pack("<H", len(offsets) - 1) + struct.pack("<%dH" % len(offsets), *offsets)
    buf += bytes(data)
    assert len(buf) <= PAGE, len(buf)
    return buf.ljust(PAGE, b"\x00")


def mapping(layout_, version, entries, used=None, phys=None):
    phys = len(entries) if phys is None else phys
    if layout_ == cimreader.LAYOUT_WIN7:
        out = struct.pack("<6I", 0xABCD, version, version + 1, version, phys, len(entries))
        for i, e in enumerate(entries):
            out += struct.pack("<6I", e, 0, 0, (used or {}).get(i, 0), 0, 0)
    else:
        out = struct.pack("<4I", 0xABCD, version, phys, len(entries))
        out += b"".join(struct.pack("<I", e) for e in entries)
    return out + struct.pack("<I", 0) + struct.pack("<I", 0xDCBA)


class Builder(object):
    """Lay objects into data pages and keys into a two-level index, then write the files."""

    def __init__(self, layout_=cimreader.LAYOUT_WIN7):
        self.layout = layout_
        self.hash_chars = 64 if layout_ == cimreader.LAYOUT_WIN7 else 32
        self.pages = []              # logical data pages: list of [toc entries, bytearray]
        self.cur = None
        self.keys = []
        self.next_id = 0x100

    def h(self, name):
        f = hashlib.sha256 if self.layout == cimreader.LAYOUT_WIN7 else hashlib.md5
        return f(name.upper().encode("utf-16-le")).hexdigest().upper()

    def _new_page(self):
        self.cur = [[], bytearray()]
        self.pages.append(self.cur)

    def place(self, path, obj):
        rid = self.next_id
        self.next_id += 7
        if len(obj) > PAGE // 2:
            # a large object starts a fresh page and runs on into the following ones
            self._new_page()
            first = PAGE - 32
            self.cur[0].append((rid, 32, len(obj)))
            self.cur[1] += obj[:first]
            start = len(self.pages) - 1
            rest = obj[first:]
            while rest:
                self.pages.append([None, bytearray(rest[:PAGE])])
                rest = rest[PAGE:]
            self.cur = None
            page = start
        else:
            if self.cur is None or 16 * (len(self.cur[0]) + 2) + len(self.cur[1]) + len(obj) > PAGE - 64:
                self._new_page()
            self.cur[0].append((rid, None, len(obj)))
            self.cur[1] += obj
            page = len(self.pages) - 1
        self.keys.append("%s.%d.%d.%d" % (path, page, rid, len(obj)))

    def key(self, path):
        self.keys.append(path)

    def _data_page(self, page):
        toc, body = page
        if toc is None:
            return bytes(body).ljust(PAGE, b"\x00")
        head = 16 * (len(toc) + 1)
        if toc and toc[0][1] == 32:
            out = struct.pack("<4I", toc[0][0], 32, toc[0][2], 0) + b"\x00" * 16 + bytes(body)
            return out[:PAGE]
        out = b""
        off = head
        lens = [e[2] for e in toc]
        for (rid, _, size) in toc:
            out += struct.pack("<4I", rid, off, size, 0)
            off += size
        out += b"\x00" * 16 + bytes(body)
        return out.ljust(PAGE, b"\x00")

    def write(self, folder, split_mapping=False):
        os.makedirs(folder, exist_ok=True)
        keys = sorted(self.keys)
        mid = len(keys) // 2
        # logical index pages: 0 admin (root_page field), 1 root, 2 left leaf, 3 right leaf
        ipages = [
            index_page([], [0], sig=cimreader.PAGE_TYPE_ADMIN, root_page=1),
            index_page([keys[mid]], [2, 3], logical=1),
            index_page(keys[:mid], [0] * (mid + 1), logical=2),
            index_page(keys[mid + 1:], [0] * (len(keys) - mid), logical=3),
        ]
        dpages = [self._data_page(p) for p in self.pages]
        # physical order is the reverse of logical order, so a reader that ignores the
        # mapping reads the wrong pages
        dmap = [len(dpages) - 1 - i for i in range(len(dpages))]
        imap = [len(ipages) - 1 - i for i in range(len(ipages))]
        with open(os.path.join(folder, "OBJECTS.DATA"), "wb") as f:
            for phys in range(len(dpages)):
                f.write(dpages[dmap.index(phys)])
        with open(os.path.join(folder, "INDEX.BTR"), "wb") as f:
            for phys in range(len(ipages)):
                f.write(ipages[imap.index(phys)])
        if split_mapping:
            with open(os.path.join(folder, "OBJECTS.MAP"), "wb") as f:
                f.write(mapping(self.layout, 9, dmap))
            with open(os.path.join(folder, "INDEX.MAP"), "wb") as f:
                f.write(mapping(self.layout, 9, imap))
            return
        good = mapping(self.layout, 20, dmap) + mapping(self.layout, 20, imap, used={0: 1})
        # an older generation that maps everything one page off: picking it fails the tests
        stale = mapping(self.layout, 19, [(p + 1) % len(dmap) for p in dmap]) + \
            mapping(self.layout, 19, imap, used={0: 2})
        with open(os.path.join(folder, "MAPPING1.MAP"), "wb") as f:
            f.write(stale)
        with open(os.path.join(folder, "MAPPING2.MAP"), "wb") as f:
            f.write(good + b"\x00" * 4)


# ----------------------------------------------------------- the known content

SUB = "root\\subscription"
DEF = "root\\default"
SYS = "__SystemClass"

SYSTEM_CLASSES = {
    "__SystemClass": Cls("__SystemClass"),
    "__namespace": Cls("__namespace", "__SystemClass", [Prop("Name", T_STRING, key=True)]),
    "__IndicationRelated": Cls("__IndicationRelated", "__SystemClass"),
    "__EventFilter": Cls("__EventFilter", "__IndicationRelated", [
        Prop("CreatorSID", T_UINT8, array=True), Prop("EventNamespace", T_STRING),
        Prop("Name", T_STRING, key=True), Prop("Query", T_STRING), Prop("QueryLanguage", T_STRING)]),
    "__EventConsumer": Cls("__EventConsumer", "__IndicationRelated", [
        Prop("CreatorSID", T_UINT8, array=True), Prop("MachineName", T_STRING),
        Prop("MaximumQueueSize", T_UINT32, default=7)]),
    "__FilterToConsumerBinding": Cls("__FilterToConsumerBinding", "__IndicationRelated", [
        Prop("Consumer", T_REF, key=True), Prop("Filter", T_REF, key=True),
        Prop("DeliverSynchronously", T_BOOL)]),
}
SUB_CLASSES = {
    "CommandLineEventConsumer": Cls("CommandLineEventConsumer", "__EventConsumer", [
        Prop("CommandLineTemplate", T_STRING), Prop("KillTimeout", T_UINT32, default=42),
        Prop("Name", T_STRING, key=True), Prop("RunInteractively", T_BOOL), Prop("Priority", T_SINT16)]),
    "ActiveScriptEventConsumer": Cls("ActiveScriptEventConsumer", "__EventConsumer", [
        Prop("Name", T_STRING, key=True), Prop("ScriptingEngine", T_STRING), Prop("ScriptText", T_STRING)]),
    "Unrelated": Cls("Unrelated", None, [Prop("Name", T_STRING, key=True), Prop("Count", T_UINT32)]),
}
ALL = dict(SYSTEM_CLASSES, **SUB_CLASSES)

SID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
SCRIPT = "\r\n".join("' synthetic line %04d" % i for i in range(1000))      # about 22 KiB, three pages
FILTER_NAME = "synthetic filter é日"
CMD = "cmd.exe /c echo synthetic é"

INSTANCES = [
    (SUB, "__EventFilter", {"CreatorSID": SID, "EventNamespace": "root\\cimv2", "Name": FILTER_NAME,
                            "Query": "SELECT * FROM __InstanceCreationEvent WITHIN 5", "QueryLanguage": "WQL"}),
    (SUB, "__EventFilter", {"Name": "second filter", "Query": "SELECT 1", "QueryLanguage": "WQL"}),
    (SUB, "CommandLineEventConsumer", {"CreatorSID": SID, "CommandLineTemplate": CMD, "KillTimeout": DEFAULT,
                                       "MaximumQueueSize": DEFAULT, "Name": "cmd consumer",
                                       "RunInteractively": False, "Priority": -3}),
    (SUB, "ActiveScriptEventConsumer", {"Name": "script consumer", "ScriptingEngine": "VBScript",
                                        "ScriptText": SCRIPT}),
    (SUB, "__FilterToConsumerBinding", {
        "Filter": '__EventFilter.Name="%s"' % FILTER_NAME,
        "Consumer": 'CommandLineEventConsumer.Name="cmd consumer"', "DeliverSynchronously": True}),
    (SUB, "__FilterToConsumerBinding", {
        "Filter": '__EventFilter.Name="second filter"',
        "Consumer": 'ActiveScriptEventConsumer.Name="script consumer"'}),
    (SUB, "Unrelated", {"Name": "not a subscription", "Count": 3}),
    (DEF, "__EventFilter", {"Name": "default filter", "Query": "SELECT 2", "QueryLanguage": "WQL"}),
]


def build(folder, layout_=cimreader.LAYOUT_WIN7, split_mapping=False, extra=()):
    b = Builder(layout_)
    ns = lambda n: "NS_" + b.h(n)                                     # noqa: E731
    for name in SYSTEM_CLASSES:
        b.place("%s/CD_%s" % (ns(SYS), b.h(name)), class_definition(ALL, name))
    for name in SUB_CLASSES:
        b.place("%s/CD_%s" % (ns(SUB), b.h(name)), class_definition(ALL, name))
    for parent, child in (("root", "subscription"), ("root", "default")):
        obj = instance(ALL, "__namespace", {"Name": child}, b.hash_chars)
        b.place("%s/CI_%s/IL_%s" % (ns(parent), b.h("__namespace"), b.h(child)), obj)
    for i, (n, cls, values) in enumerate(list(INSTANCES) + list(extra)):
        kw = values.pop("_kw", {}) if "_kw" in values else {}
        obj = instance(ALL, cls, values, b.hash_chars, **kw)
        b.place("%s/CI_%s/IL_%s" % (ns(n), b.h(cls), b.h(str(i))), obj)
        b.key("%s/KI_%s/I_%s" % (ns(n), b.h(cls), b.h(str(i))))     # an index key with no data
    b.write(folder, split_mapping)
    return folder


@pytest.fixture(scope="module")
def win7_repo(tmp_path_factory):
    return build(str(tmp_path_factory.mktemp("win7") / "Repository"))


# ------------------------------------------------------------------- tests

def by_name(rows):
    return {r["properties"].get("Name") or r["properties"].get("Filter"): r for r in rows}


def test_info_picks_highest_mapping_and_reads_it(win7_repo):
    with cimreader.open_repository(win7_repo) as repo:
        info = cimreader._info(repo)
    assert info["layout"] == "win7"
    assert info["mapping_files"] == ["MAPPING2.MAP"]
    assert info["mapping_versions"] == {"MAPPING1.MAP": 19, "MAPPING2.MAP": 20}
    assert info["root_index_page"] == 1
    assert info["root_index_page_signature"] == "0xaccc"
    assert info["mapping_file_size"] - info["mapping_bytes_used"] == 4


def test_namespaces(win7_repo):
    with cimreader.open_repository(win7_repo) as repo:
        assert repo.namespaces() == ["root", "root\\subscription", "root\\default"]


def test_classes_include_system_classes(win7_repo):
    with cimreader.open_repository(win7_repo) as repo:
        names = repo.class_names(SUB)
    # index (hash) order, system classes first
    assert sorted(names[:len(SYSTEM_CLASSES)]) == sorted(SYSTEM_CLASSES)
    assert sorted(names[len(SYSTEM_CLASSES):]) == sorted(SUB_CLASSES)


def test_prefix_lookup_equals_full_walk(win7_repo):
    with cimreader.open_repository(win7_repo) as repo:
        every = [k.s for k in repo.iter_keys()]
        assert every == sorted(every)
        for prefix in ("NS_", repo.NS(SUB), "%s/%s" % (repo.NS(SYS), repo.CD()),
                       "%s/%s/%s" % (repo.NS(SUB), repo.CI("__EventFilter"), repo.IL())):
            assert [k.s for k in repo.lookup(prefix)] == [k for k in every if prefix in k]


def test_subscriptions_decode_every_value(win7_repo):
    with cimreader.open_repository(win7_repo) as repo:
        res = cimreader.subscriptions(repo)
    assert res["errors"] == []
    sub = by_name(res["namespaces"][SUB])
    assert sorted(r["kind"] for r in sub.values()) == sorted(
        ["__EventFilter"] * 2 + ["__EventConsumer"] * 2 + ["__FilterToConsumerBinding"] * 2)
    assert "not a subscription" not in sub

    f = sub[FILTER_NAME]
    assert f["properties"] == {"CreatorSID": SID, "EventNamespace": "root\\cimv2", "Name": FILTER_NAME,
                               "Query": "SELECT * FROM __InstanceCreationEvent WITHIN 5",
                               "QueryLanguage": "WQL"}
    assert f["errors"] == []
    assert f["timestamp_1"] == cimreader.filetime_to_iso(0x01DC000000000001)

    second = sub["second filter"]
    assert second["properties"]["CreatorSID"] is None and second["properties"]["EventNamespace"] is None

    c = sub["cmd consumer"]
    assert c["class"] == "CommandLineEventConsumer"
    assert c["derivation"] == ["__SystemClass", "__IndicationRelated", "__EventConsumer", "CommandLineEventConsumer"]
    assert c["properties"]["CommandLineTemplate"] == CMD
    assert c["properties"]["KillTimeout"] == 42              # the class's own default
    assert c["properties"]["MaximumQueueSize"] == 7          # a default an ancestor holds
    assert c["properties"]["RunInteractively"] is False
    assert c["properties"]["Priority"] == -3
    assert c["properties"]["MachineName"] is None
    assert sorted(c["from_class_default"]) == ["KillTimeout", "MaximumQueueSize"]
    assert c["property_types"]["CreatorSID"] == "uint8[]"

    s = sub["script consumer"]
    assert s["properties"]["ScriptText"] == SCRIPT           # spans three data pages
    assert s["location"]["length"] > 2 * PAGE and s["location"]["pages"] == 3
    with cimreader.open_repository(win7_repo) as repo:
        with open(os.path.join(win7_repo, "OBJECTS.DATA"), "rb") as fh:
            for row in sub.values():
                loc = row["location"]
                assert loc["file_offset"] // PAGE == loc["physical_page"]
                key = [k for k in repo.iter_keys() if k.is_data_reference and k.data_id == loc["record_id"]][0]
                assert loc["physical_page"] == repo.data_mapping.physical(key.data_page)
                if loc["pages"] == 1:
                    # the record's bytes sit at file_offset in the file itself
                    fh.seek(loc["file_offset"])
                    assert fh.read(loc["length"]) == repo.object_bytes(key)

    b = sub['__EventFilter.Name="%s"' % FILTER_NAME]
    assert b["properties"]["Consumer"] == 'CommandLineEventConsumer.Name="cmd consumer"'
    assert b["properties"]["DeliverSynchronously"] is True

    assert [r["properties"]["Name"] for r in res["namespaces"][DEF]] == ["default filter"]


def test_string_encodings():
    assert cimreader._wmi_string(b"\x00caf\xe9\x00", 0) == "café"
    assert cimreader._wmi_string(b"\x01" + "日x".encode("utf-16-le") + b"\x00\x00", 0) == "日x"
    # a UTF-16 string whose code unit ends in a zero byte, followed by the terminator
    assert cimreader._wmi_string(b"\x01" + "Ā".encode("utf-16-le") + b"\x00\x00", 0) == "Ā"
    with pytest.raises(cimreader.CimError):
        cimreader._wmi_string(b"\x05abc\x00", 0)
    with pytest.raises(cimreader.CimError):
        cimreader._wmi_string(b"\x00abc", 0)


def test_xp_split_mapping(tmp_path):
    folder = build(str(tmp_path / "Repository" / "FS"), cimreader.LAYOUT_XP, split_mapping=True)
    with cimreader.open_repository(str(tmp_path / "Repository")) as repo:
        assert repo.layout == "xp"
        assert repo.directory == folder
        assert repo.root_index_page_number == 1          # from the admin page's root field
        res = cimreader.subscriptions(repo)
    sub = by_name(res["namespaces"][SUB])
    assert sub["cmd consumer"]["properties"]["KillTimeout"] == 42
    assert sub["script consumer"]["properties"]["ScriptText"] == SCRIPT


def test_dynamic_properties_are_refused_per_instance(tmp_path):
    extra = [(SUB, "__EventFilter", {"Name": "dyn", "_kw": {"dynprops": 2}})]
    with cimreader.open_repository(build(str(tmp_path / "r"), extra=extra)) as repo:
        rows = by_name(cimreader.subscriptions(repo)["namespaces"][SUB])
        bad = [i for i in repo.instances(SUB, "__EventFilter") if i.errors]
    assert len(bad) == 1 and "dynamic properties" in bad[0].errors[0]
    assert FILTER_NAME in rows


def test_truncated_objects_data_is_an_error(tmp_path):
    folder = build(str(tmp_path / "r"))
    p = os.path.join(folder, "OBJECTS.DATA")
    with open(p, "r+b") as f:
        f.truncate(os.path.getsize(p) - 100)
    with cimreader.open_repository(folder) as repo:
        res = cimreader.subscriptions(repo)
    flat = res["errors"] + [e for rows in res["namespaces"].values() for r in rows for e in r["errors"]]
    assert flat, "a short page must surface as an error, not as fewer objects"


def test_bad_mapping_footer_is_refused(tmp_path):
    folder = build(str(tmp_path / "r"))
    p = os.path.join(folder, "MAPPING2.MAP")
    data = bytearray(open(p, "rb").read())
    i = data.rfind(struct.pack("<I", 0xDCBA))
    data[i:i + 4] = b"\x00\x00\x00\x00"
    open(p, "wb").write(bytes(data))
    with pytest.raises(cimreader.CimError):
        cimreader.open_repository(folder)


def test_command_line_subscriptions(win7_repo):
    out = io.StringIO()
    with redirect_stdout(out):
        rc = cimreader.main(["subscriptions", win7_repo])
    assert rc == 0
    res = json.loads(out.getvalue())
    assert len(res["namespaces"][SUB]) == 6 and len(res["namespaces"][DEF]) == 1


def test_command_line_reports_unreadable_input(tmp_path, capsys):
    assert cimreader.main(["info", str(tmp_path)]) == 1
    assert "OBJECTS.DATA" in capsys.readouterr().err


def test_filetime():
    assert cimreader.filetime_to_iso(0) is None
    assert cimreader.filetime_to_iso(116444736000000000) == "1970-01-01T00:00:00Z"
