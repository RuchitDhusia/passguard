import argparse
import getpass
import sys

from .analyzer import analyze
from .generator import generate


def _bar(score):
    return "[" + "#" * (score + 1) + "-" * (4 - score) + "]"


def _check(args):
    pw = args.password
    if pw is None:
        pw = getpass.getpass("Password (hidden): ")
    r = analyze(pw)
    print(f"Strength   : {r.label} {_bar(r.score)}")
    print(f"Length     : {r.length}")
    print(f"Entropy    : ~{r.entropy_bits} bits")
    print(f"Crack time : {r.crack_time} (offline, fast hash, estimate)")
    if r.issues:
        print("\nIssues:")
        for i in r.issues:
            print(f"  - {i}")
    if r.tips:
        print("\nTips:")
        for t in dict.fromkeys(r.tips):
            print(f"  - {t}")
    return 0 if r.score >= 3 else 1


def _generate(args):
    try:
        for _ in range(args.count):
            print(generate(args.length, not args.no_symbols))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="passguard",
        description="Offline password strength checker and generator.")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="analyze a password")
    c.add_argument("password", nargs="?",
                   help="omit this to type it hidden (safer, no shell history)")
    c.set_defaults(func=_check)

    g = sub.add_parser("generate", help="generate a random password")
    g.add_argument("-l", "--length", type=int, default=16)
    g.add_argument("-n", "--count", type=int, default=1)
    g.add_argument("--no-symbols", action="store_true")
    g.set_defaults(func=_generate)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
