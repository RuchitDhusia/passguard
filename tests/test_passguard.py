import string
import unittest

from passguard import analyze, generate
from passguard.generator import SYMBOLS


class AnalyzerTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(analyze("").score, 0)

    def test_common_password_is_weak(self):
        self.assertLessEqual(analyze("password123").score, 1)

    def test_leet_variant_is_flagged(self):
        r = analyze("P@ssw0rd")
        self.assertTrue(any("common" in i for i in r.issues))

    def test_sequence_flagged(self):
        r = analyze("xyzabc123Kq")
        self.assertTrue(any("sequence" in i for i in r.issues))

    def test_repeat_flagged(self):
        r = analyze("aaaKq91!zz")
        self.assertTrue(any("identical" in i for i in r.issues))

    def test_long_random_is_strong(self):
        self.assertGreaterEqual(analyze("tR7#vLq9!xWm2$Zp").score, 3)

    def test_longer_scores_higher(self):
        self.assertGreater(analyze("Kq7#mRt2Xv9!").entropy_bits,
                           analyze("Kq7#mRt2").entropy_bits)


class GeneratorTests(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(generate(20)), 20)

    def test_has_all_classes(self):
        for _ in range(50):
            pw = generate(12)
            self.assertTrue(any(c in string.ascii_lowercase for c in pw))
            self.assertTrue(any(c in string.ascii_uppercase for c in pw))
            self.assertTrue(any(c in string.digits for c in pw))
            self.assertTrue(any(c in SYMBOLS for c in pw))

    def test_no_symbols(self):
        pw = generate(30, symbols=False)
        self.assertFalse(any(c in SYMBOLS for c in pw))

    def test_too_short(self):
        with self.assertRaises(ValueError):
            generate(4)

    def test_generated_is_strong(self):
        self.assertGreaterEqual(analyze(generate(16)).score, 3)


if __name__ == "__main__":
    unittest.main()
