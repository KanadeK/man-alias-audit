"""Literal roff aliases are edges, not programs to execute."""
from collections import Counter, defaultdict
import bz2
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zlib

MAX_FILE = 8 * 1024 * 1024
MAX_PAGES = 50_000
MAX_HOPS = 256
SUFFIXES = ('.gz', '.bz2', '.xz', '.zst', '.Z', '.z', '.lz', '.lzma')
SUPPORTED = ('', '.gz', '.bz2', '.xz')
SECTION = re.compile(r'man(?:[0-9][A-Za-z0-9]*|[nl])\Z')
PAGE = re.compile(r'.+\.(?:[0-9][A-Za-z0-9]*|[nl])\Z')


class AuditError(ValueError):
    """The selected tree cannot be audited completely."""


def split_compression(name):
    for suffix in SUFFIXES:
        if name.endswith(suffix):
            return name[:-len(suffix)], suffix
    return name, ''


def reparse_directory(path):
    info = path.lstat()
    return path.is_symlink() or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def read_text(path, suffix):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise AuditError('not a regular page file')
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise AuditError('compressed/raw file exceeds size limit')
    if suffix:
        if suffix == '.gz':
            decoder = zlib.decompressobj(31)
        elif suffix == '.bz2':
            decoder = bz2.BZ2Decompressor()
        elif suffix == '.xz':
            decoder = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024)
        else:
            raise AuditError('unsupported compression')
        data = decoder.decompress(data, MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise AuditError('expanded page exceeds size limit')
        if not decoder.eof or decoder.unused_data:
            raise AuditError('truncated, concatenated or trailing compressed stream')
    try:
        return data.decode('utf-8')
    except UnicodeError as exc:
        raise AuditError('page is not UTF-8') from exc


def classify(text):
    lines = []
    for line in text.splitlines():
        # Literal requests only. Removing comments does not evaluate roff escapes.
        line = line.split('\\"', 1)[0].rstrip()
        if line.strip() in ('', '.', "'"):
            continue
        lines.append(line)
    if not lines:
        return {'kind': 'invalid', 'code': 'empty-page'}
    includes = [line for line in lines if re.match(r"[.']\s*so", line)]
    # A conditional/include expression cannot be treated as a proven terminal.
    includes += [line for line in lines if line.startswith('.') and re.search(r'\s\.so(?:\s|$)', line)]
    if not includes:
        return {'kind': 'regular'}
    if len(lines) != 1 or not re.match(r'\.so\s+', lines[0]):
        return {'kind': 'unsupported', 'code': 'nonliteral-or-mixed-roff'}
    parts = lines[0].split()
    if len(parts) != 2 or any(char in parts[1] for char in '\\"\''):
        return {'kind': 'unsupported', 'code': 'nonliteral-or-mixed-roff'}
    return {'kind': 'so', 'target': parts[1]}


def normalize_target(target, parent='', directories=None):
    if not target or target.startswith('/') or '\\' in target or ':' in target:
        raise AuditError('absolute, empty, drive or backslash target')
    if any(ord(char) < 32 for char in target):
        raise AuditError('control character in target')
    if target.endswith('/'):
        raise AuditError('target has a trailing directory separator')
    stack = list(PurePosixPath(parent).parts) if parent else []
    for part in target.split('/'):
        if directories is not None and '/'.join(stack) not in directories:
            raise AuditError('intermediate directory is absent or outside the flat man tree')
        if part in ('', '.'):
            continue
        if part == '..':
            if not stack:
                raise AuditError('target escapes selected root')
            stack.pop()
        else:
            stack.append(part)
    return '/'.join(stack)


def discover(root):
    nodes = {}
    findings = []
    ignored = []
    directories = {''}
    scanned = 0

    def children(directory):
        nonlocal scanned
        result = []
        for entry in directory.iterdir():
            scanned += 1
            if scanned > MAX_PAGES * 2:
                raise AuditError('tree enumeration exceeds entry limit')
            result.append(entry)
        return sorted(result, key=lambda p: p.name)

    for section in children(root):
        if not SECTION.fullmatch(section.name):
            ignored.append(section.name)
            continue
        if reparse_directory(section):
            findings.append({'code': 'linked-section-directory', 'path': section.name})
            continue
        if not section.is_dir():
            findings.append({'code': 'section-not-directory', 'path': section.name})
            continue
        directories.add(section.name)
        for path in children(section):
            key = f'{section.name}/{path.name}'
            logical, suffix = split_compression(path.name)
            if not PAGE.fullmatch(logical):
                ignored.append(key)
                continue
            if len(nodes) >= MAX_PAGES:
                raise AuditError('page count exceeds 50000')
            node = {'path': key, 'compression': suffix}
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    node.update(kind='symlink', target=os.readlink(path))
                elif getattr(info, 'st_file_attributes', 0) & 0x400:
                    node.update(kind='invalid', code='unsupported-reparse-point')
                elif not stat.S_ISREG(info.st_mode):
                    node.update(kind='invalid', code='special-or-directory-page')
                elif suffix not in SUPPORTED:
                    node.update(kind='unsupported', code='unsupported-compression')
                else:
                    node.update(classify(read_text(path, suffix)))
            except (OSError, ValueError, EOFError, zlib.error, lzma.LZMAError) as exc:
                node.update(kind='invalid', code='unreadable-page', detail=str(exc))
            nodes[key] = node
    if not nodes and not findings:
        raise AuditError('no manpage files found; select one root containing man1, man3, etc.')
    return nodes, findings, ignored, directories


def audit(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise AuditError('root must be a directory')
    nodes, findings, ignored, directories = discover(root)
    variants = defaultdict(list)
    for key in nodes:
        logical, _ = split_compression(key)
        variants[logical].append(key)
    for logical, paths in sorted(variants.items()):
        if len(paths) > 1:
            findings.append({'code': 'competing-variants', 'path': logical, 'candidates': paths})

    edges = {}
    for key, node in nodes.items():
        if node['kind'] not in ('so', 'symlink'):
            continue
        try:
            parent = str(PurePosixPath(key).parent) if node['kind'] == 'symlink' else ''
            raw_target = node['target']
            if node['kind'] == 'symlink' and os.name == 'nt':
                raw_target = raw_target.replace('\\', '/')
            target = normalize_target(raw_target, parent, directories)
            candidates = [target] if target in nodes else []
            # A kernel symlink must name a real file exactly: it has no .gz fallback.
            if not candidates and node['kind'] == 'so' and split_compression(target)[1] == '':
                candidates = variants.get(target, [])
            if not candidates:
                edges[key] = {'code': 'missing-target', 'requested': target}
            elif len(candidates) > 1:
                edges[key] = {'code': 'ambiguous-compression', 'requested': target, 'candidates': candidates}
            else:
                edges[key] = {'to': candidates[0], 'requested': target}
        except AuditError as exc:
            edges[key] = {'code': 'unsafe-target', 'detail': str(exc)}

    results = []
    for key, node in nodes.items():
        result = {'path': key, 'kind': node['kind']}
        if 'target' in node:
            result['target'] = node['target']
        chain = []
        seen = set()
        current = key
        while True:
            if current in seen:
                result.update(status='failed', code='cycle', chain=chain + [current])
                break
            if len(chain) >= MAX_HOPS:
                result.update(status='unverified', code='hop-limit', chain=chain, next=current)
                break
            seen.add(current)
            chain.append(current)
            at = nodes[current]
            if at['kind'] == 'regular':
                result.update(status='regular' if key == current else 'resolved', code='terminal-page',
                              chain=chain, terminal=current)
                break
            if at['kind'] in ('invalid', 'unsupported'):
                result.update(status='failed' if at['kind'] == 'invalid' else 'unverified',
                              code=at['code'], chain=chain)
                if 'detail' in at:
                    result['detail'] = at['detail']
                break
            edge = edges[current]
            if 'to' not in edge:
                result.update(status='failed', chain=chain, **edge)
                break
            current = edge['to']
        results.append(result)
    counts = Counter(item['status'] for item in results)
    summary = {key: counts[key] for key in ('regular', 'resolved', 'failed', 'unverified')}
    summary['policy_findings'] = len(findings)
    return {'schema_version': 1, 'pages': len(nodes), 'aliases': len(edges), 'summary': summary,
            'passed': counts['failed'] == counts['unverified'] == 0 and not findings,
            'findings': findings, 'ignored': ignored, 'results': results}
