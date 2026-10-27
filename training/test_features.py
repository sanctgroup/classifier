import unittest

from training import features


class FeatureTests(unittest.TestCase):
    def test_vectorize_is_deterministic(self):
        first = features.vectorize("Hello", "Meeting moved to 3pm, see https://example.com/x")
        second = features.vectorize("Hello", "Meeting moved to 3pm, see https://example.com/x")
        self.assertEqual(first, second)
        self.assertTrue(all(0 <= i < features.DIM for i in first))

    def test_empty_input_still_has_meta_features(self):
        vector = features.vectorize("", "")
        self.assertTrue(vector)

    def test_urls_are_reduced_to_host_words(self):
        groups = features.tokens("", "Login at https://secure-paypal.example.ru/verify?id=1 now")
        meta, _, _, body_words, _ = groups
        self.assertIn("m:url:1", meta)
        self.assertIn("m:tld:ru", meta)
        self.assertIn("w:paypal", body_words)
        self.assertNotIn("w:verify", body_words)

    def test_ip_urls_and_zero_width_are_flagged(self):
        meta = features.tokens("", "Go to http://203.0.113.9/login​ please")[0]
        self.assertIn("m:urlip", meta)
        self.assertIn("m:zw", meta)

    def test_numbers_are_shape_normalized(self):
        body_words = features.tokens("", "Order 123456789 total 42")[3]
        self.assertIn("w:999999", body_words)
        self.assertIn("w:99", body_words)

    def test_words_follow_spec(self):
        self.assertEqual(features.words("Don't STOP_me now'x 'ok"), ["don't", "stop", "me", "now'x", "ok"])
        self.assertEqual(features.words("a'b'c"), ["a'b", "c"])
        self.assertEqual(features.words("Grüße ΣΟΦΟΣ 東京2024"), ["grüße", "σοφος", "東京9999"])

    def test_snippet_view_matches_smtp_inbound(self):
        self.assertEqual(features.snippet_view("Subj", "x" * 500), ("", "x" * 200))
        self.assertEqual(features.snippet_view("Subj", "  "), ("", "Subj"))

    def test_long_bodies_are_bounded(self):
        vector = features.vectorize("s", "word " * 100_000)
        self.assertLess(len(vector), 5_000)


if __name__ == "__main__":
    unittest.main()
