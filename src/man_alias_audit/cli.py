import argparse
import json
import sys

from . import __version__
from .core import AuditError, audit


def main(argv=None):
    parser = argparse.ArgumentParser(description='Audit a staged manpage alias tree without executing roff.')
    parser.add_argument('root', help='one man root containing man1, man3, etc. (one locale at a time)')
    parser.add_argument('--json', action='store_true', help='emit a complete machine-readable report')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        report = audit(args.root)
    except (OSError, RuntimeError, AuditError) as exc:
        print('man-alias-audit: ' + json.dumps(str(exc)), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print(f"{report['pages']} pages, {report['aliases']} aliases; " +
              ', '.join(f'{v} {k}' for k, v in report['summary'].items()))
        for finding in report['findings']:
            print(finding['code'] + ': ' + json.dumps(finding))
        for result in report['results']:
            if result['status'] != 'regular':
                print(result['status'] + ': ' + json.dumps(result))
        print(f"{len(report['ignored'])} entries outside the selected manpage naming/layout scope")
        print('PASS' if report['passed'] else 'FAIL')
    return 0 if report['passed'] else 1
