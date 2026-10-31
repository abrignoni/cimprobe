# cimprobe

A read-only reader for the Windows WMI CIM repository, the files Windows keeps in
`C:\Windows\System32\wbem\Repository` (`OBJECTS.DATA`, `INDEX.BTR` and
`MAPPING1.MAP` to `MAPPING3.MAP`). One file, pure Python, standard library only.

It resolves the active page mapping, walks the index B-tree, and decodes namespaces,
class definitions and class instances against their class definitions. Its first job is
listing WMI event subscriptions: `__EventFilter`, the `__EventConsumer` subclasses
(`CommandLineEventConsumer`, `ActiveScriptEventConsumer` and the rest) and
`__FilterToConsumerBinding`. A permanent subscription is a common persistence
mechanism, and the repository is where it lives.

```python
import cimprobe

with cimprobe.open_repository("Repository") as repo:
    for inst in repo.instances("root\\subscription", "CommandLineEventConsumer"):
        print(inst.properties["Name"], inst.properties["CommandLineTemplate"])
```

## Where it comes from

cimprobe is a port of **python-cim**, part of Mandiant's
[flare-wmi](https://github.com/mandiant/flare-wmi), written by Willi Ballenthin with
contributions from davidpany and fhouse. The structures, constants and lookup logic are
python-cim's, ported from `python-cim/cim/cim.py` and `python-cim/cim/objects.py` at
commit `b0a5a094ff9ca7d7a1c4fc711dc00c74dec4b6b1` (2018-07-23). python-cim is
licensed under the Apache License 2.0, and so is cimprobe; see `LICENSE` and `NOTICE`.

python-cim was archived in 2018. It needs `vivisect-vstruct-wb`, which is published on
PyPI only as a source distribution, so it does not install where only wheels are
allowed. cimprobe replaces the vstruct structure definitions with `struct` reads and
drops the other dependencies, so it can be copied into a tool as one file.

## Command line

```
cimprobe info          Repository            # layout, active mapping, page counts
cimprobe namespaces    Repository            # every namespace below root
cimprobe classes       Repository root\subscription
cimprobe instances     Repository root\subscription CommandLineEventConsumer
cimprobe subscriptions Repository            # root\subscription and root\default, as JSON
cimprobe subscriptions Repository --namespace root\cimv2
cimprobe keys          Repository [--prefix NS_...]
```

The path can be the `Repository` folder or the `wbem` folder that holds it.
`instances` and `subscriptions` exit with 2 when any object could not be decoded, so
"nothing there" and "could not read" are never the same answer.

`subscriptions` reports every instance, in each namespace asked for, of a class that is
`__EventFilter`, `__EventConsumer` or `__FilterToConsumerBinding` or derives from one of
them. Consumer classes are found by their derivation, not by a list of names, so a
consumer class a product registers is reported too. Each instance carries its
properties by name (`null` where the instance marks a property as not set), which
properties took the class default, the class derivation, the two timestamps at the
head of the record (see below) and where the record is: its logical page, the physical
page the active mapping puts it on, its record id and length, the byte offset of its
first byte in `OBJECTS.DATA`, and how many pages it spans.

`tools/census.py` prints counts only (namespaces, instances listed against instances
decoded, errors by kind, subscription objects by kind), for reporting on a repository
whose contents cannot be shared.

## What it reads

- **The layout python-cim calls `win7`**: three `MAPPING*.MAP` files, of which the one
  with the highest version is the active mapping, as python-cim does it. Read on
  Windows 7, 8.1, 10, 11 and Server 2012 R2, 2019 and 2022 repositories (below).
- **The layout python-cim calls `xp`**, in two forms:
  - an early Windows XP repository that keeps its mapping in
    `Repository\FS\OBJECTS.MAP` and `INDEX.MAP` instead of `MAPPING*.MAP`. That form
    is not in python-cim. On the one image measured (corpus key
    `cfreds_hacking_case_winxp`, build 2600, no service pack), each of the two files is
    exactly one mapping in python-cim's XP structure, both signatures in place and every
    byte read, and the whole repository walks (below).
  - python-cim's own `xp` form, with `MAPPING*.MAP`. Only one such mapping file has
    been read, python-cim's `tests/repos/xp/mapping-only` sample, which has no data or
    index files: it is detected as `xp`, its two mappings parse with both signatures in
    place, and 1,072 bytes follow them. No objects have been read in this form.
- **Only the live view**: the objects the active mapping and the index reach. A deleted
  or superseded object left in a free page is not read, so it is never reported as
  live, and it is not recovered either.

## What is proven, and how

Four tiers, kept apart.

**Data-proven against Windows itself (known data).** On the Parallels "Windows 11
arm" VM (Windows 11 build 26200), a harmless set of permanent subscriptions was created
with `New-CimInstance` on 2026-10-31: in `root\subscription` two filters, a
`CommandLineEventConsumer` and an `ActiveScriptEventConsumer` whose script is about
15 KB (larger than one 8 KB page) and two bindings; in `root\default` a filter, a
`LogFileEventConsumer` and a binding. A filter name and a command line held non-ASCII
characters, some properties were set and others left at their class default, and the
command line was changed once a minute later. The repository was copied out of a VSS
shadow copy four times (before creation, after creation, after the change, after
removal), each copy checked by SHA-256 on the VM and again on the Mac, and each time
the live view was exported with `Get-CimInstance -Shallow` for every class in
`root\subscription` and `root\default`, with each property's name, CIM type, flags and
value. Compared instance by instance and property by property:

| capture | instances in the export | matched | properties equal | subscription objects |
|---|---|---|---|---|
| before creation | 40 | 39 | 416 of 416 | 3 |
| after creation | 49 | 48 | 498 of 498 | 12 |
| after the change | 49 | 48 | 498 of 498 | 12 |
| after removal | 40 | 39 | 416 of 416 | 3 |

The one instance in each capture that does not match is `SystemRestoreConfig` in
`root\default`, which carries dynamic properties; cimprobe refuses it with an error
rather than decode it (see "Not supported"). cimprobe also reports one
`__thisNAMESPACE` instance per namespace that the export did not list. After removal,
cimprobe reports only the three stock objects again: the removed objects are not
reported as live. In the same captures, the class names cimprobe lists for
`root\subscription` (70) and `root\default` (79) are exactly the classes
`Get-CimClass` lists.

The scripts that created, changed, removed and exported the known data, and the
comparison itself, are in `tools/known-data/`. The captures are not in this repository.

**Exercised on the corpus, with no oracle.** The repositories in eleven disk images from
the DLEAPP corpus were read in full. Every one opens, its root index page carries the
active signature, and every subscription object decodes without error. Counts only:

| corpus key | layout | namespaces | instances listed / decoded clean | subscription objects |
|---|---|---|---|---|
| cfreds_hacking_case_winxp | xp | 26 | 751 / 750 | 6 |
| cfreds_leakage_win7 | win7 | 47 | 1,945 / 1,861 | 6 |
| alihadi_challenge3_win81 | win7 | 86 | 2,398 / 2,314 | 3 |
| af_case2_win10 | win7 | 93 | 2,492 / 2,406 | 3 |
| lonewolf_win10 | win7 | 95 | 2,545 / 2,459 | 3 |
| szechuan_win10 | win7 | 94 | 2,573 / 2,487 | 3 |
| pc_mus_001_win11 | win7 | 83 | 2,460 / 2,374 | 3 |
| hexordia_mvs2025_win11 | win7 | 144 | 2,847 / 2,757 | 3 |
| szechuan_dc01_server2012r2 | win7 | 80 | 2,455 / 2,372 | 3 |
| alihadi_threatsim_server2019 | win7 | 106 | 2,664 / 2,579 | 3 |
| ou_ransomware_server2022 | win7 | 107 | 2,667 / 2,582 | 3 |

The instances that do not decode clean are instances whose classes hold embedded
objects or dynamic properties, the same kinds on every image (see "Not supported");
none is a subscription object.

**python-cim's own test data.** python-cim's tests assert figures "collected
empirically" from a Windows 7 repository in its `tests/repos/win7/deleted-instance`.
`tests/test_python_cim_reference.py` reads that repository and reproduces every figure
those tests record: mapping sizes and the unmapped page list, the index root page, the
47,490 keys its lookup returns for `NS_`, the data page count and the first page's
table of contents, 55 namespaces, 8,162 classes, the qualifier, property and layout
property counts, and 1,887 instances. Three differences are deliberate and the test
computes python-cim's figure from cimprobe's output to show it:
- python-cim's lookup visits the child between two matching keys twice, so its 47,490
  keys are 14,481 distinct ones; cimprobe returns the 14,481, which is what a full
  index walk finds.
- python-cim yields one instance per value of the class's own key properties, so the
  instances of a class without its own key collapse into one. cimprobe yields all
  1,972 instances the index lists; 1,887 is what remains after python-cim's rule.
- python-cim decodes the one instance with dynamic properties while ignoring them (5
  properties); cimprobe refuses it.

python-cim is not run on these; this compares cimprobe with the results its authors
recorded. The CI workflow fetches those files at the pinned commit.

**python-cim run side by side.** python-cim at the pinned commit, on Python 3.10, read
the four known-data captures and ten of the corpus images listed above, every instance in
every namespace, next to cimprobe (`tools/python_cim_side_by_side.py`, counts and names
only). The XP image is left out: python-cim opens only `MAPPING1.MAP` to `MAPPING3.MAP`,
not the split `Repository\FS` layout. Across the fourteen repositories:

| | instances |
|---|---|
| cimprobe lists | 34,910 |
| python-cim lists | 33,426 |
| identical in both | 27,752 |
| listed by cimprobe only | 1,484 |
| refused by cimprobe, returned by python-cim without error | 1,173 |
| in both, differing | 4,501 |

- The 1,484 sit in classes where python-cim lists fewer instances than cimprobe, 82 to
  124 per repository. That fits its merge by the leaf class's own key, described above;
  this run did not test the rule instance by instance.
- 3,434 boolean values read True in python-cim and False in cimprobe; none differ the
  other way. python-cim decodes a boolean as `value != 0` on a vstruct `v_uint16`, and
  vivisect-vstruct-wb 1.0.3 defines no comparison for it, so the test is always true.
  Where the known-data export covers them (`root\subscription` and `root\default`), it
  agrees with cimprobe.
- 3,342 of the differing instances name the built-in property 0x6 `PROVIDER` in
  python-cim and `provider` in cimprobe (see below).
- 8 text values differ on the created and modified captures: the subscription objects
  holding non-ASCII characters. The export agrees with cimprobe.
- Not explained by this run: 84 ASCII string values (`Name` and `Description`, six in
  every repository), 146 string-array values (`Text`, all on hexordia_mvs2025_win11) and
  38 values initialized in one reader only (`QuerySupportLevels`). Which reader is right
  is not established. Instances that differ are paired with the closest instance of the
  same class, so some of these may compare two different instances.
- Whether python-cim's values for the 1,173 instances cimprobe refuses are right is not
  established.

python-cim took 12 to 26 seconds per repository, cimprobe 1 to 4.

**Synthetic tests.** `tests/test_cimprobe.py` builds repositories with a small writer
that lives only in the tests and checks that the reader returns what went in: mapping
generation choice, both layouts and the split XP mapping, the index walk against prefix
lookups, defaults held by the class and by an ancestor, an object spanning three pages,
both string encodings, and refusals for a short page, a bad mapping footer and dynamic
properties. That is a second reading of the same description, not evidence.

**Not measured.** python-cim was not run on the XP image. The `xp` layout has no oracle.
Windows Vista and 8.0 repositories have not been read.

## What known data showed that python-cim does not say

- **Strings.** A string in a data region is one byte, then the text. With the byte at
  0 the text is one byte per character up to a NUL; with the byte at 1 it is UTF-16LE
  up to a two-byte NUL. On the known data, a string whose characters all fit Latin-1
  was stored with 0 (and the export matched it read as Latin-1), and strings holding
  characters beyond Latin-1 were stored with 1. python-cim skips the byte and decodes
  UTF-8, which gives the wrong text for any non-ASCII string of either kind.
- **The method part of a class definition** has a size that counts its own four bytes.
  python-cim reads it like the property region, whose size does not, and so asks for
  four bytes past the object. All 6,750 class definitions in the known-data repository
  end exactly where the self-counting size puts the end.
- **The two timestamps at the head of an instance**, which python-cim calls ts1 and ts2
  without saying what they are, are reported as `timestamp_1` and `timestamp_2`. On
  the known data, neither matched when an instance was created or changed (one
  creation and one change were measured):
  - `timestamp_2` equals the timestamp of the instance's own class definition, on every
    one of 28,254 instances across the known-data repository and the eleven corpus
    repositories.
  - `timestamp_1` on the nine objects created at 13:41:44 UTC on 2026-10-31 read
    2026-10-26T18:08:29.481173Z or .481174Z, five days earlier, and the change made a
    minute later moved it by one 100 ns tick. The stock objects read 2024-04-01. What
    it counts is not established.
- **Property type flags.** The second byte of a property type takes the values 0x00,
  0x20, 0x40 and 0x60. python-cim treats only 0x20 as an array. Reading the 0x20 bit
  as the array flag instead gave identical output on all 2,475 instances the
  known-data repository's namespace walk reaches, so the difference is not exercised by any data at hand and
  python-cim's test is kept.
- **One built-in property name** (0x6) is `provider` in the live view, on the provider
  registration classes; python-cim labels it `PROVIDER`. The other built-in names keep
  python-cim's labels.
- **Classes from class providers are not stored.** `root\cimv2` lists 1,312 classes
  live and 862 in the repository; 453 of the live ones are `Win32_Perf*` classes a
  provider supplies. cimprobe lists what the repository holds.
- **A namespace can be in the index without being reachable from root**: on the known
  data, one localized (`ms_409`) namespace holds classes and instances while its
  parent's namespace record is not stored. `tools/census.py` counts such namespaces;
  cimprobe's namespace walk does not name them.
- The active `win7` mapping file ends with bytes no structure accounts for: four bytes
  in every `win7` repository measured but one, which has forty, zero in some
  repositories and not in others. They are not read. The split XP mapping files have
  none.

## Not supported

- **Embedded object properties** (CIM type 13), alone or in arrays: the property is
  reported as `null` with an error on the instance. No subscription class in any
  repository measured uses one.
- **Instances with dynamic properties** (flag 2): python-cim's parser for them is
  incomplete, so the instance is refused with an error rather than misread.
- **char16 properties** (CIM type 0x67): python-cim does not know the type's width, so
  an instance of a class holding one is refused with an error.
- **Deleted, superseded or orphaned objects** in free pages or older mapping
  generations, and recovery of any kind.
- **Instance key hashes.** Like python-cim, cimprobe lists instances by prefix and does
  not compute the hash an instance is filed under.

## Tests

```
python -m pytest tests -q
```

No dependencies beyond pytest. Run locally on Python 3.10, 3.12 and 3.14, with the
python-cim reference test included:

```
CIMPROBE_PYCIM_REPOS=/path/to/flare-wmi/python-cim/tests/repos python -m pytest tests -q
```

The CI workflow runs 3.10 to 3.14 on Linux, 3.10 and 3.14 on Windows and 3.14 on
macOS, each with the python-cim reference test required.

## Licence

Apache License 2.0, as python-cim. `NOTICE` names python-cim's authors and the commit
ported from.
