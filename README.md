# passguard

Offline password strength checker and secure password generator for the command line. Pure Python, standard library only, nothing is sent over the network.

## Features

- Entropy based strength score (Very weak to Very strong)
- Detects common passwords, including leetspeak variants like `P@ssw0rd`
- Flags repeated characters and sequences (`aaa`, `abc`, `123`, `qwe`)
- Estimated offline crack time
- Hidden password prompt so it never lands in your shell history
- Generator built on Python's `secrets` module (CSPRNG)

## Requirements

Python 3.8 or newer.

## Usage

```bash
# check a password (prompts with hidden input)
python -m passguard check

# check directly (stays in shell history, use only for testing)
python -m passguard check 'P@ssw0rd'

# generate passwords
python -m passguard generate
python -m passguard generate -l 24 -n 5
python -m passguard generate --no-symbols
```

`check` exits with code `0` for Strong or better and `1` otherwise, so it can be used in scripts.

Example:

```
$ python -m passguard check 'P@ssw0rd'
Strength   : Very weak [#----]
Length     : 8
Entropy    : ~10.0 bits
Crack time : instantly (offline, fast hash, estimate)

Issues:
  - Matches or closely resembles a very common password.
  - Short (8 characters).
```

## How it works

1. The character pool is detected (lowercase, uppercase, digits, symbols) and entropy is estimated as `length * log2(pool)`.
2. Penalties apply for repeats and sequences. Common passwords are capped at a very low entropy.
3. Score bands: under 28 bits very weak, under 36 weak, under 60 fair, under 80 strong, otherwise very strong.
4. Crack time assumes an offline attack at 10 billion guesses per second against a fast unsalted hash.

## Limitations

- The common password list is small and built in. It is not a replacement for a full breached password database.
- Entropy is an estimate. It does not model dictionary words or personal info (names, birthdays).
- Crack time is a rough guide, not a guarantee.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Project structure

```
passguard/
  analyzer.py    strength analysis
  generator.py   password generator
  cli.py         command line interface
tests/
  test_passguard.py
```

## License

MIT
