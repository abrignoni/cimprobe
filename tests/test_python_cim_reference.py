"""cimreader against python-cim's own test repositories and recorded results.

python-cim's tests (flare-wmi commit b0a5a09, python-cim/tests/test_mapping.py,
test_index.py, test_logical_pages.py and test_object_resolver.py) assert counts
"collected empirically" from a Windows 7 repository in its tests/repos/win7/
deleted-instance folder, and test_mapping.py checks layout detection on
tests/repos/xp/mapping-only. Those files are not in this repository; point
CIMREADER_PYCIM_REPOS at a copy of python-cim/tests/repos taken at that commit (the CI
workflow fetches them). Set CIMREADER_REQUIRE_PYCIM_REPOS=1 to fail rather than skip
when they are missing.

Every number below is python-cim's. Where cimreader deliberately behaves differently,
the test computes python-cim's figure from cimreader's output the way python-cim
arrives at it, and says why the two differ.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cimreader  # noqa: E402

REPOS = os.environ.get("CIMREADER_PYCIM_REPOS", "")
WIN7 = os.path.join(REPOS, "win7", "deleted-instance")
XP = os.path.join(REPOS, "xp", "mapping-only")

if not (REPOS and os.path.isfile(os.path.join(WIN7, "OBJECTS.DATA"))):
    if os.environ.get("CIMREADER_REQUIRE_PYCIM_REPOS"):
        raise RuntimeError("CIMREADER_PYCIM_REPOS does not point at python-cim's tests/repos")
    pytest.skip("python-cim's test repositories are not available", allow_module_level=True)


@pytest.fixture(scope="module")
def repo():
    with cimreader.open_repository(WIN7) as r:
        yield r


def test_layout_detection():
    with open(os.path.join(XP, "MAPPING1.MAP"), "rb") as f:
        assert cimreader.guess_layout(f.read(24)) == cimreader.LAYOUT_XP
    with open(os.path.join(WIN7, "MAPPING1.MAP"), "rb") as f:
        assert cimreader.guess_layout(f.read(24)) == cimreader.LAYOUT_WIN7


def test_mappings(repo):
    im, dm = repo.index_mapping, repo.data_mapping
    assert (len(im), im.physical_page_count, im.physical(0)) == (326, 547, 13)
    assert (len(dm), dm.physical_page_count, dm.physical(0)) == (1727, 1886, 0)
    assert [i for i in range(len(im)) if not im.is_mapped(i)] == [
        91, 160, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 227, 228, 230]


def test_index(repo):
    assert repo.root_index_page_number == 60
    # python-cim's lookup returns 47,490 keys for "NS_" because it walks the child
    # between two matching keys twice; cimreader's lookup removes the repeats, and the
    # full walk, which visits each page once, agrees with it.
    raw = repo._lookup("NS_", repo.index_page(repo.root_index_page_number), 0)
    assert len(raw) == 47490
    distinct = repo.lookup("NS_")
    assert len(distinct) == len({k.s for k in raw})
    assert [k.s for k in distinct] == [k.s for k in repo.iter_keys()]


def test_data_pages(repo):
    assert repo.data_page_count == 1886
    assert len(cimreader._parse_toc(repo.data_page(0))) == 22


def test_object_counts(repo):
    names = repo.namespaces()
    # root and the 54 namespaces below it; python-cim counts those 54 plus __SystemClass
    assert len(names) == 55
    everywhere = names + [cimreader.SYSTEM_NAMESPACE_NAME]
    classes = [(ns, c) for ns in everywhere for c in repo.class_names(ns)]
    assert len(classes) == 8162

    qualifiers = props = prop_quals = layout_props = 0
    instances = deduped = instance_props = 0
    dynamic_refused = 0
    for ns, c in classes:
        cd = repo.class_definition(ns, c)
        qualifiers += len(cd.qualifiers)
        own = {p.name: p for p in cd.properties}
        props += len(own)
        prop_quals += sum(len(p.qualifiers) for p in own.values())
        layout = repo.class_layout(ns, c)
        layout_props += len({p.name for p in layout.properties_by_index})
        seen = set()
        for inst in repo.instances(ns, c):
            instances += 1
            # python-cim yields one instance per value of the leaf class's own key
            # properties ("default" when there are none), so instances of a class
            # without its own key collapse into one. cimreader yields every instance.
            k = ",".join("%s=%s" % (n, inst.properties.get(n)) for n in sorted(cd.key_names)) or "default"
            if k in seen:
                continue
            seen.add(k)
            deduped += 1
            if any("dynamic properties" in e for e in inst.errors):
                # python-cim decodes it while ignoring the dynamic properties; cimreader refuses it
                dynamic_refused += len(layout.properties_by_index)
            instance_props += len(inst.properties)
    assert (qualifiers, props, prop_quals) == (17650, 27431, 66948)
    assert layout_props == 53867
    assert deduped == 1887
    assert instances == 1972
    assert dynamic_refused == 5
    assert instance_props + dynamic_refused == 8237
