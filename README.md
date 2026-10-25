# man-alias-audit

Find broken manpage aliases in a staged package **before installation**. Follow
literal `.so` stubs and filesystem symlinks, with a readable chain explaining
missing targets, cycles and compression ambiguity. Read-only, offline,
Python 3.11+, no runtime dependencies and no roff/formatter execution.

[中文说明](README.zh-CN.md) · [MIT](LICENSE)

A common packaging trap: `.so man1/tool.1` can resolve to `tool.1.gz`, but a
symlink pointing to `tool.1` cannot. The tool models those as different edge types.

## Install and run

```sh
git clone https://github.com/KanadeK/man-alias-audit.git
cd man-alias-audit
python -m pip install .
man-alias-audit staging/usr/share/man --json
```

The root is one man hierarchy containing immediate `man1`, `man3`, etc.
For translations, audit each locale root separately, for example
`man-alias-audit staging/usr/share/man/fr`.
`python -m man_alias_audit` is equivalent to the console command.

A self-contained demo, including a compressed terminal page:

```sh
python examples/make_demo.py demo-good
man-alias-audit demo-good
python examples/make_demo.py demo-bad --broken
man-alias-audit demo-bad --json
```

The first audit returns 0 and follows `hi.1 -> hello.1 -> greet.1.gz`.
The second returns 1 and identifies the missing target in both affected chains.
The generator refuses to overwrite existing directories. Remove the generated
demo directories when finished. Uninstall with
`python -m pip uninstall man-alias-audit`; the auditor writes no caches or indexes.

## Resolution rules

1. Literal `.so` paths are relative to the supplied **man root**, matching a
   man-db-style staged hierarchy. A bare `.so base.1` does not mean the alias's
   own directory. Use `.so man1/base.1`.
2. Filesystem symlinks resolve relative to their parent directory, must name a
   discovered page exactly, and never receive compression fallback.
3. `.so` uses an exact filename when present. If it is absent and no compression
   extension was explicitly named, a single discovered compression variant is used.
   Multiple candidates produce `ambiguous-compression`, with all candidates shown.
4. Any coexisting compression variants produce `competing-variants` and fail the
   policy, even when an exact `.so` target exists. This is deliberately stricter
   than one zsoelim invocation: different installation/lookup policies may pick
   different variants. Remove the stale variant or audit the intended final tree.
5. Chains ending at an ordinary page are `resolved`. Cycles show the repeated
   node. Upstream aliases inherit missing, unsafe, unreadable or unsupported outcomes.

Plain, gzip, bzip2 and xz **single-stream UTF-8** page files are supported, including
compressed `.so` stubs. Other recognized suffixes (`.zst`, `.Z`, `.z`, `.lz`,
`.lzma`) remain unverified; they are never silently treated as text.

Literal stubs may contain blank lines and roff `\"` comments. Mixed content,
quoted/dynamic targets, alternate control characters, conditional `.so` requests
and unsupported include syntax are reported as unverified. Ordinary terminal
pages are only classified as having no recognized include request: their roff
syntax, rendered content, macro behavior and NAME sections are **not validated**.

## Output and CI

| Exit | Meaning |
|---|---|
| 0 | All discovered aliases resolve; no unsupported pages or policy findings |
| 1 | Failed/unverified chains, unsupported pages, or competing/unsafe layout findings |
| 2 | Invalid root, empty selection, resource limit during discovery, or usage error |

JSON `schema_version: 1` contains page/alias counts, outcome counts, tree-level
findings, ignored paths and per-page chains. `regular` means an ordinary terminal
page, not a proof of correct formatting. `resolved` refers to aliases only.
Reports are deterministic and use root-relative paths. Human output JSON-quotes
untrusted strings. The same exit codes work in CI:

```sh
man-alias-audit package-root/usr/share/man --json
```

Library API:

```python
from man_alias_audit import audit
report = audit('package-root/usr/share/man')
assert report['passed'], report['findings']
```

## Scope and alternatives

[mandb -t](https://manpages.debian.org/trixie/man-db/mandb.8.en.html) already
checks manual hierarchies without altering its databases, including bad `.so`
requests and competing extensions. Use it for native man-db checks. This tool
adds a portable Python workflow, structured chain evidence and explicit handling
of incomplete support on Windows as well as Unix. It is not a replacement for
mandb, mandoc, groff or a full rendering test.

[zsoelim](https://manpages.debian.org/trixie/man-db/zsoelim.1.en.html) documents
compressed include fallback. Its compiled-in extensions and preference order can
differ; the auditor refuses ambiguous fallbacks instead of guessing that order.
The implementation and demo content are original; native tools are test-only.

The scan is intentionally flat: one locale's `man<section>/<page>.<section>`
files. Other roots/files and nested directories are listed as ignored; no recursive
locale discovery, cross-root MANPATH search, installed `/usr/share/man` remapping,
arbitrary roff macros or formatter programs are modeled. Absolute paths, escaping
paths, directory symlinks/junctions and special files are rejected. Only discovered
section directories may occur in intermediate path components, so a nonexistent
directory cannot be erased with `..` to produce a false match. Filenames are
case-sensitive. Windows filesystem symlink separators are normalized, while
backslashes in roff targets require unsupported escape interpretation.

Limits: 8 MiB raw and expanded bytes per file, 64 MiB xz decoder memory,
50,000 pages, 100,000 enumerated tree entries, 256 nodes per chain. Concatenated
compression streams and trailing compressed bytes fail explicitly. Use a stable
staged tree; concurrent replacement is outside the threat model. There is no
repair mode and no automatic link/file deletion.

## Development and validation

```sh
python -m pip install -e . -r requirements-dev.txt
python -m unittest discover -s tests -v
ruff check .
python -m build
```

Tests cover compressed chains, ambiguity, cycles, exact symlink semantics,
boundary paths, input limits, non-UTF-8/corrupt data, CLI and read-only behavior.
Symlink/FIFO tests skip when unavailable. A native integration test compares an
original gzip include chain with `zsoelim`; it skips if man-db is absent locally.
Linux CI installs man-db and requires that native test to run. CI also tests
Python 3.11/3.13 on Windows and builds the package.
