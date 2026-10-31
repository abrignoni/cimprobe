"""Count what cimreader reads in a repository, and what it could not read.

    python tools/census.py <Repository folder> [...]

Prints one JSON object per repository: the layout, the namespace count, the namespace
hashes in the index that the namespace walk does not name, every class instance the
index lists against how many the walk decoded, decode errors grouped by message, and
the subscription objects by kind. Counts only: no names, values or paths from inside
the repository, so the output can be shared about evidence that cannot.
"""

import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cimreader  # noqa: E402

_HEX = re.compile(r"0x[0-9a-f]+|\d+")


def census(path):
    out = {"repository": path}
    try:
        repo = cimreader.open_repository(path)
    except cimreader.CimError as exc:
        out["open_error"] = str(exc)
        return out
    with repo:
        out["layout"] = repo.layout
        out["mapping_versions"] = sorted(repo.mapping_versions.values())
        out["mapping_bytes_unread"] = repo.mapping_file_size - repo.mapping_bytes_used
        out["root_index_page_signature"] = "0x%04x" % repo.index_page(repo.root_index_page_number).sig
        try:
            keys = list(repo.iter_keys())
        except cimreader.CimError as exc:
            out["index_walk_error"] = str(exc)
            return out
        out["index_keys"] = len(keys)
        shapes = collections.Counter(
            "/".join(p.split("_")[0] for p in k.s.split("/")) + ("." if k.is_data_reference else "")
            for k in keys)
        out["index_key_shapes"] = dict(shapes.most_common())
        try:
            names = repo.namespaces()
        except cimreader.CimError as exc:
            out["namespace_walk_error"] = str(exc)
            names = [cimreader.ROOT_NAMESPACE_NAME]
        out["namespaces"] = len(names)
        named = {repo.NS(n) for n in names + [cimreader.SYSTEM_NAMESPACE_NAME]}
        index_ns = {k.s.split("/")[0] for k in keys}
        out["namespace_hashes_not_named"] = len(index_ns - named)
        errors = collections.Counter()
        seen = set()
        classes = 0
        decoded = 0
        for ns in names + [cimreader.SYSTEM_NAMESPACE_NAME]:
            try:
                cls = repo.class_names(ns)
            except cimreader.CimError as exc:
                errors["class list: " + _HEX.sub("N", str(exc))] += 1
                continue
            for name in cls:
                if ns != cimreader.SYSTEM_NAMESPACE_NAME:
                    classes += 1
                try:
                    for inst in repo.instances(ns, name):
                        seen.add(inst.key.s)
                        if inst.errors:
                            for e in inst.errors:
                                errors[_HEX.sub("N", e.split(": ", 1)[-1] if e.startswith("property ") else e)] += 1
                        else:
                            decoded += 1
                except cimreader.CimError as exc:
                    errors["class: " + _HEX.sub("N", str(exc))] += 1
        listed = [k for k in keys if k.is_data_reference and k.s.split("/")[1:2] and k.s.split("/")[1].startswith("CI_")]
        out["classes_visible"] = classes
        out["instances_listed"] = len(listed)
        out["instances_reached"] = len(seen)
        out["instances_decoded_without_error"] = decoded
        out["errors"] = dict(errors.most_common())
        subs = cimreader.subscriptions(repo)
        out["subscriptions"] = {
            ns: dict(collections.Counter(r["kind"] for r in rows)) for ns, rows in subs["namespaces"].items()}
        out["subscription_consumer_classes"] = {
            ns: dict(collections.Counter(r["class"] for r in rows if r["kind"] == "__EventConsumer"))
            for ns, rows in subs["namespaces"].items()}
        out["subscription_errors"] = len(subs["errors"]) + sum(
            len(r["errors"]) for rows in subs["namespaces"].values() for r in rows)
    return out


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(json.dumps(census(p), indent=1))
