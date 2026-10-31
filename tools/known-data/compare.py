"""Compare cimprobe's decoded instances with the Get-CimInstance export (oracle.ps1),
per namespace, per class, per instance, per property.

    python compare.py <cimprobe folder> <capture folder holding oracle.json and Repository>

Instances are paired by their class's key properties. What is normalised before two
values are compared, and why:
- A property the export flags NullValue must be None in cimprobe.
- PowerShell unrolls a one-element array returned from a function, so the export writes
  a one-element array as its element; it is wrapped back into a list.
- The export writes a reference as the referenced instance's key properties, and
  cimprobe as the stored object path; both become (class, sorted key values), lowercased
  class and key names.
- The export writes a DMTF interval as a .NET TimeSpan string; cimprobe's stored DMTF
  interval string is converted to the same form. A DMTF datetime is left as stored.
- Key property names are matched without regard to case.
"""
import sys, json, re, collections
sys.path.insert(0, sys.argv[1])
import cimprobe as c

cap = sys.argv[2]
oracle = json.load(open(cap + "/oracle.json", encoding="utf-8-sig"))
repo = c.open_repository(cap + "/Repository")
REF = re.compile(r'^(?:\\\\[^\\]+\\[^:]+:)?([^.]+)\.(.*)$')

def norm_ref(v):
    m = REF.match(v)
    if not m: return v
    keys = {}
    for part in re.findall(r'(\w+)=("(?:[^"\\]|\\.)*"|[^,]+)', m.group(2)):
        k, val = part
        if val.startswith('"'): val = val[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        keys[k.lower()] = val
    return (m.group(1).lower(), tuple(sorted(keys.items())))

def norm_oracle(p):
    v = p["Value"]
    # PowerShell unrolls a one-element array returned from a function, so the oracle
    # writes a one-element array as its element; put it back.
    if p["CimType"].endswith("Array") and v is not None and not isinstance(v, list):
        v = [v]
    if isinstance(v, dict) and "interval" in v:
        return ("interval", v["interval"])
    if isinstance(v, dict) and "datetime" in v:
        return ("datetime", v["datetime"])
    if p["CimType"] == "Reference" and isinstance(v, dict):
        return (v["embedded"].lower(), tuple(sorted((q["Name"].lower(), str(q["Value"])) for q in v["props"] if q["Value"] is not None)))
    return v

DMTF_IV = re.compile(r'^(\d{8})(\d{2})(\d{2})(\d{2})\.(\d{6}):000$')
def norm_mine(v, t):
    if t == "reference" and isinstance(v, str): return norm_ref(v)
    if t == "datetime" and isinstance(v, str):
        m = DMTF_IV.match(v)
        if m:
            d, H, M, S, us = m.groups(); d = int(d)
            frac = ("." + us.rstrip("0").ljust(7, "0")) if int(us) else ""
            return ("interval", ("%d." % d if d else "") + "%s:%s:%s%s" % (H, M, S, frac))
        return ("datetime-dmtf", v)
    return v

tot = collections.Counter()
problems = []
for ns, block in oracle["namespaces"].items():
    by_class = collections.defaultdict(list)
    for row in block["instances"]:
        by_class[row["ClassName"]].append(row)
    for cls, rows in sorted(by_class.items()):
        try:
            mine = list(repo.instances(ns, cls))
        except c.CimError as e:
            problems.append(("class-error", ns, cls, str(e), rows[0]["ClassQualifiers"])); tot["class_error"] += 1; continue
        tot["oracle_instances"] += len(rows); tot["cimprobe_instances"] += len(mine)
        keys = repo.class_layout(ns, cls).key_names
        def okey(r):
            d = {p["Name"].lower(): p for p in r["Properties"]}
            return tuple(repr(norm_oracle(d[k.lower()])) if k.lower() in d else None for k in keys)
        def mkey(i): return tuple(repr(norm_mine(i.properties.get(k), i.property_types.get(k))) for k in keys)
        mm = {mkey(i): i for i in mine}
        if len(mm) != len(mine): problems.append(("dup-key", ns, cls, len(mine), len(mm)))
        for r in rows:
            i = mm.pop(okey(r), None)
            if i is None:
                problems.append(("missing", ns, cls, okey(r), r["ClassQualifiers"])); tot["missing"] += 1; continue
            if i.errors: problems.append(("errors", ns, cls, okey(r), i.errors)); tot["inst_with_errors"] += 1
            tot["matched_instances"] += 1
            onames = [p["Name"] for p in r["Properties"]]
            if set(onames) != set(i.properties): problems.append(("propset", ns, cls, okey(r), sorted(set(onames) ^ set(i.properties))))
            for p in r["Properties"]:
                tot["props"] += 1
                if p["Name"] not in i.properties: continue
                mv = norm_mine(i.properties[p["Name"]], i.property_types[p["Name"]])
                ov = norm_oracle(p)
                if "NullValue" in p["Flags"]:
                    ok = mv is None
                else:
                    ok = mv == ov
                if ok: tot["props_equal"] += 1
                else:
                    tot["props_differ"] += 1
                    problems.append(("value", ns, cls, okey(r), p["Name"], p["CimType"], p["Flags"], repr(ov)[:120], repr(mv)[:120]))
        for k, i in mm.items():
            problems.append(("extra", ns, cls, k)); tot["extra"] += 1
    # instances cimprobe sees in classes the oracle reports none for
    seen = set(by_class)
    for cls in repo.class_names(ns):
        if cls in seen: continue
        try:
            n = len(list(repo.instances(ns, cls)))
        except c.CimError as e:
            continue
        if n:
            problems.append(("extra-class", ns, cls, n)); tot["extra"] += n
print(json.dumps(tot, indent=1))
for p in problems[:80]: print(p)
print("problems:", len(problems))
