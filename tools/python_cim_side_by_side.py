"""Read one WMI repository with python-cim and with cimprobe, side by side.

Every instance in every namespace both readers reach. Prints counts, property names, CIM
type names and difference categories only, never a value. Instances identical in both
are counted; each remaining python-cim instance is paired with the closest remaining
cimprobe instance of the same class (most equal properties), and every property that
differs is put in a category.

python-cim is not a dependency of cimprobe. Point the first argument at a checkout of
mandiant/flare-wmi's python-cim folder (measured with commit b0a5a09) and run this with
an interpreter that has its requirements (funcy, hexdump, intervaltree,
vivisect-vstruct-wb); its Qt viewer packages are not needed.

usage: python_cim_side_by_side.py PYTHON_CIM_DIR LABEL LAYOUT REPOSITORY_DIR
"""
import collections
import json
import logging
import os
import sys
import time

sys.path.insert(0, sys.argv[1])
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

import cim  # noqa: E402
from cim.objects import Tree  # noqa: E402
import cimprobe  # noqa: E402

logging.disable(logging.CRITICAL)
UNINIT = "<uninit>"


def norm(v):
    if v is None:
        return UNINIT
    if isinstance(v, (list, tuple)):
        return [norm(x) for x in v]
    if isinstance(v, bytes):
        return v.hex()
    return str(v)


def pycim_side(tree):
    out = collections.defaultdict(list)       # (NS, CLASS) -> [(props, pytypes) | None]
    names, errors = [], collections.Counter()
    stack, seen = [tree.root], set()
    while stack:
        ns = stack.pop()
        if ns.name.upper() in seen:
            continue
        seen.add(ns.name.upper())
        names.append(ns.name)
        try:
            stack.extend(ns.namespaces)
        except Exception as exc:  # noqa: BLE001
            errors["namespace children: " + type(exc).__name__] += 1
        try:
            classes = list(ns.classes)
        except Exception as exc:  # noqa: BLE001
            errors["class list: " + type(exc).__name__] += 1
            continue
        for c in classes:
            try:
                insts = list(c.instances)
            except Exception as exc:  # noqa: BLE001
                errors["instance list: " + type(exc).__name__] += 1
                continue
            for i in insts:
                key = (ns.name.upper(), i.class_name.upper())
                try:
                    props, pytypes = {}, {}
                    for name, p in i.properties.items():
                        if p.is_initialized:
                            props[name] = norm(p.value)
                            pytypes[name] = type(p.value).__name__
                        else:
                            props[name] = UNINIT
                    out[key].append((props, pytypes))
                except Exception as exc:  # noqa: BLE001
                    errors["instance decode: " + type(exc).__name__] += 1
                    out[key].append(None)
    return out, names, errors


def cimprobe_side(repo):
    out = collections.defaultdict(list)       # (NS, CLASS) -> [(props, cimtypes, keynames) | None]
    names = repo.namespaces()
    for ns in names:
        for cname in repo.class_names(ns):
            try:
                keynames = repo.class_layout(ns, cname).key_names
                insts = list(repo.instances(ns, cname))
            except cimprobe.CimError:
                continue
            for i in insts:
                key = (ns.upper(), i.class_name.upper())
                if i.errors:
                    out[key].append(None)
                else:
                    out[key].append(({k: norm(v) for k, v in i.properties.items()},
                                     dict(i.property_types), keynames))
    return out, names


def category(pv, cv, cimtype, pytype):
    if pv == UNINIT or cv == UNINIT:
        return "one side not initialized"
    cimtype = (cimtype or "").upper()
    if "BOOLEAN" in cimtype or cv in ("True", "False"):
        return "boolean: python-cim %s, cimprobe %s" % (pv if pv in ("True", "False") else "raw " + pytype, cv)
    if isinstance(cv, list) or isinstance(pv, list):
        return "array (%s)" % cimtype
    if pv.lower() == cv.lower():
        return "same text, different case (%s)" % cimtype
    if any(s in cimtype for s in ("STRING", "REFERENCE", "DATETIME")):
        kind = "ASCII" if cv.isascii() else "non-ASCII"
        if pv.isdigit() and not cv.isdigit():
            return "%s: python-cim gives a number for a %s cimprobe value" % (cimtype, kind)
        return "%s: text differs, cimprobe value %s" % (cimtype, kind)
    if pv.lstrip("-").isdigit() and cv.lstrip("-").isdigit():
        return "number differs (%s)" % cimtype
    return "other (%s, python-cim %s)" % (cimtype, pytype)


def canon(props):
    return json.dumps(props, sort_keys=True, ensure_ascii=False)


def main():
    label, layout, path = sys.argv[2:5]
    t0 = time.time()
    pc, pc_names, pc_errors = pycim_side(Tree(cim.CIM(layout, path)))
    t1 = time.time()
    with cimprobe.open_repository(path) as repo:
        cp, cp_names = cimprobe_side(repo)
    t2 = time.time()

    res = collections.Counter()
    cats = collections.Counter()
    cat_props = collections.defaultdict(collections.Counter)
    name_gaps = collections.Counter()
    count_gap = collections.Counter()
    for key in sorted(set(pc) | set(cp)):
        a, b = pc.get(key, []), cp.get(key, [])
        res["python-cim instances"] += len(a)
        res["cimprobe instances"] += len(b)
        res["python-cim decode errors"] += a.count(None)
        res["cimprobe refused"] += b.count(None)
        if len(a) != len(b):
            keyed = any(x and x[2] for x in b)
            count_gap["%s; class %s own key" % (
                "python-cim fewer" if len(a) < len(b) else "python-cim more",
                "with" if keyed else "without")] += abs(len(a) - len(b))
        a = [x for x in a if x]
        b = [x for x in b if x]
        ca = collections.Counter(canon(x[0]) for x in a)
        cb = collections.Counter(canon(x[0]) for x in b)
        res["identical"] += sum((ca & cb).values())
        left_a = list((ca - cb).elements())
        left_b = list((cb - ca).elements())
        pa = [next(x for x in a if canon(x[0]) == k) for k in left_a]
        pb = [next(x for x in b if canon(x[0]) == k) for k in left_b]
        refused_here = cp.get(key, []).count(None)
        for xa in pa:
            props_a, pytypes = xa
            if not pb:
                res["python-cim instance unpaired: %s" % (
                    "cimprobe refused one of this class" if refused_here else "no cimprobe instance left in class")] += 1
                continue
            partner = max(pb, key=lambda xb: sum(1 for n in props_a if xb[0].get(n) == props_a[n]))
            pb.remove(partner)
            res["paired, differing"] += 1
            props_b, cimtypes, _ = partner
            for n in sorted(set(props_a) ^ set(props_b)):
                name_gaps["%s only in %s" % (n, "python-cim" if n in props_a else "cimprobe")] += 1
            for n in set(props_a) & set(props_b):
                if props_a[n] != props_b[n]:
                    c = category(props_a[n], props_b[n], cimtypes.get(n), pytypes.get(n, "uninit"))
                    cats[c] += 1
                    cat_props[c][n] += 1
        res["cimprobe instance unpaired: %s" % ("python-cim has fewer in class" if len(pc.get(key, [])) < len(cp.get(key, [])) else "other")] += len(pb)

    print(json.dumps({
        "label": label,
        "namespaces python-cim": len(pc_names),
        "namespaces cimprobe": len(cp_names),
        "namespaces only in python-cim": len({n.upper() for n in pc_names} - {n.upper() for n in cp_names}),
        "namespaces only in cimprobe": len({n.upper() for n in cp_names} - {n.upper() for n in pc_names}),
        "counts": dict(res),
        "instance count gaps": dict(count_gap),
        "python-cim errors": dict(pc_errors),
        "difference categories (property values)": dict(cats.most_common()),
        "properties per category": {c: dict(v.most_common(8)) for c, v in cat_props.items()},
        "property name gaps": dict(name_gaps.most_common(10)),
        "seconds python-cim": round(t1 - t0, 1),
        "seconds cimprobe": round(t2 - t1, 1),
    }, indent=1))


if __name__ == "__main__":
    main()
