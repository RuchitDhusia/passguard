"""Password strength analysis. Fully offline, standard library only."""
import math
import re
from dataclasses import dataclass, field

# Small built-in list of very common passwords (lowercase).
COMMON = {
    "password", "passw0rd", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "abc123", "letmein", "welcome", "admin", "login",
    "iloveyou", "monkey", "dragon", "football", "baseball", "master",
    "sunshine", "princess", "shadow", "superman", "batman", "trustno1",
    "freedom", "whatever", "hello", "secret", "india", "india123", "cricket",
    "krishna", "ganesh", "shiva", "sachin", "ranbir", "pass", "pass123",
    "admin123", "root", "toor", "test", "test123", "guest", "default",
    "changeme", "welcome1", "zaq12wsx", "asdfgh", "asdfghjkl", "zxcvbnm",
    "qazwsx", "1q2w3e4r", "111111", "000000", "121212", "654321", "696969",
}

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

LEET = str.maketrans({"@": "a", "0": "o", "3": "e", "$": "s", "5": "s",
                      "1": "i", "!": "i", "7": "t", "4": "a"})

# Rough attacker speed: offline attack on a fast, unsalted hash.
GUESSES_PER_SECOND = 1e10

LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]


@dataclass
class Result:
    length: int
    pool_size: int
    entropy_bits: float
    score: int
    label: str
    crack_time: str
    issues: list = field(default_factory=list)
    tips: list = field(default_factory=list)


def _pool_size(pw):
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[ -/:-@\[-`{-~]", pw):
        pool += 33
    if re.search(r"[^\x20-\x7e]", pw):
        pool += 32
    return pool


def _has_sequence(pw, n=3):
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - n + 1):
                if s[i:i + n] in low:
                    return True
    return False


def _is_common(pw):
    low = pw.lower()
    bases = {low, low.translate(LEET), low.rstrip("0123456789!@#$%^&*._-"),
             low.translate(LEET).rstrip("0123456789!@#$%^&*._-")}
    return any(b in COMMON for b in bases)


def _format_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 365),
             ("year", 1000)]
    value = seconds
    for name, step in units:
        if value < step:
            n = int(value)
            return f"{n} {name}{'' if n == 1 else 's'}"
        value /= step
    if value < 1000:
        return f"{int(value)} thousand years"
    return "over a million years"


def analyze(password):
    pw = password or ""
    length = len(pw)
    pool = _pool_size(pw)
    issues, tips = [], []

    if length == 0:
        return Result(0, 0, 0.0, 0, LABELS[0], "instantly",
                      ["Password is empty."], ["Use at least 12 characters."])

    entropy = length * math.log2(pool)

    if _is_common(pw):
        entropy = min(entropy, 10.0)
        issues.append("Matches or closely resembles a very common password.")
        tips.append("Avoid common words, even with digits or symbols added.")
    if re.search(r"(.)\1\1", pw):
        entropy -= 6
        issues.append("Contains 3 or more identical characters in a row.")
    if _has_sequence(pw):
        entropy -= 8
        issues.append("Contains a sequence like abc, 123 or qwe.")
    if length < 12:
        issues.append(f"Short ({length} characters).")
        tips.append("Use at least 12 characters. Length matters most.")
    if pool <= 36 and length >= 1:
        tips.append("Mix upper and lower case letters, digits and symbols.")
    if pw.isdigit():
        issues.append("Digits only.")

    entropy = max(entropy, 0.0)

    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4

    seconds = (2 ** min(entropy, 200)) / 2 / GUESSES_PER_SECOND
    return Result(length, pool, round(entropy, 1), score, LABELS[score],
                  _format_time(seconds), issues, tips)
