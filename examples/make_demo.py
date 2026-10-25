"""Create original demonstration manpages; never overwrite an existing tree."""
import argparse
import gzip
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('destination')
parser.add_argument('--broken', action='store_true')
args = parser.parse_args()
root = Path(args.destination)
root.mkdir(parents=True, exist_ok=False)
(root / 'man1').mkdir()
page = b'.TH GREET 1\n.SH NAME\ngreet \\- print a greeting\n.SH DESCRIPTION\nPrint a greeting.\n'
(root / 'man1/greet.1.gz').write_bytes(gzip.compress(page, mtime=0))
target = 'man1/missing.1' if args.broken else 'man1/greet.1'
(root / 'man1/hello.1').write_text(f'.so {target}\n', encoding='utf-8')
(root / 'man1/hi.1').write_text('.so man1/hello.1\n', encoding='utf-8')
print(root)
