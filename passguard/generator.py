"""Password generator using the secrets module (CSPRNG)."""
import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def generate(length=16, symbols=True):
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(SYMBOLS)
    if length < max(8, len(pools)):
        raise ValueError("length must be at least 8")
    # one guaranteed character from each pool, rest from the combined pool
    chars = [secrets.choice(p) for p in pools]
    combined = "".join(pools)
    chars += [secrets.choice(combined) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
