import argparse
import json
import random
import sys
import unicodedata
from array import array
from pathlib import Path

from training import datasets, features

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

EDGE_CASES = [
    ("", ""),
    ("Hello", "Plain body."),
    ("URGENT!!! ACT NOW", "Click https://secure-paypal.example.ru/verify?id=1 or www.Bank-Login.COM./x now!"),
    ("Re: lunch", "See http://203.0.113.9:8080/a and mail me at a.b+c@Example.co.uk"),
    ("<b>Sale</b>", "<html><body><p>50% OFF &nbsp; &amp; free &#8364;</p><a href='http://x.y'>link</a></body></html>"),
    ("ΣΟΦΟΣ", "ΟΔΟΣ ΣΟΦΟΣ. İstanbul ǅemal ß straße Ⅻ ½ ²"),
    ("東京2024", "お得なキャンペーン！今すぐクリック 123４５６ ｈｔｔｐｓ://ｅｘａｍｐｌｅ.ｃｏｍ"),
    ("zero​width", "fr​ee mo­ney ﻿now"),
    ("Don't", "It's a'b'c o'clock rock'n'roll ''quoted'' 'lead trail' end'"),
    ("emoji 🎉", "Win 💰💰 $1,000,000 €500 £20 ¥9 ₿1 right now!!!!!!"),
    ("ﬁnance", "ﬁle ﬂow ㎏ ℡ ① ⑳ 𝐁𝐎𝐋𝐃 𝓈𝒸𝓇𝒾𝓅𝓉"),
    ("मराठी हिंदी", "नमस्ते दुनिया क्षत्रिय العربية مرحبا"),
    ("CAPS", "THIS IS ALL CAPS TEXT WITH NO LOWER"),
    ("x" * 600, "word " * 5000),
    ("tabs\tand\nlines", "line1\r\nline2\x1c\x1dsep para end nbsp"),
    ("https://only.url", "HTTPS://UPPER.EXAMPLE.ORG/PATH Www.Mixed.Case.Net"),
    ("<", "<<>> < br> <a\nhref=x> <123> <" + "y" * 600 + ">"),
]


def unicode_tables():
    word, letter, upper, lower_map, nfkc_map, unassigned = [], [], [], {}, {}, []

    def add(ranges, cp):
        if ranges and ranges[-1][1] == cp - 1:
            ranges[-1][1] = cp
        else:
            ranges.append([cp, cp])

    for cp in range(sys.maxunicode + 1):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        c = chr(cp)
        category = unicodedata.category(c)
        if category == "Cn":
            add(unassigned, cp)
            continue
        if features.is_word_char(c):
            add(word, cp)
        if features.is_letter(c):
            add(letter, cp)
        if features.is_upper(c):
            add(upper, cp)
        lowered = c.lower()
        if lowered != c:
            lower_map[cp] = lowered
        normalized = unicodedata.normalize("NFKC", c)
        if normalized != c:
            nfkc_map[cp] = normalized
    return {
        "unicode_version": unicodedata.unidata_version,
        "word": word,
        "letter": letter,
        "upper": upper,
        "unassigned": unassigned,
        "lower": lower_map,
        "nfkc": nfkc_map,
    }


def load_weights(meta):
    weights = array("f")
    weights.frombytes((ROOT / "models" / meta["weights_file"]).read_bytes())
    if sys.byteorder != "little":
        weights.byteswap()
    return weights


def case(subject, body, weights, bias):
    vector = features.vectorize(subject, body)
    logit = bias + sum(weights[i] * v for i, v in vector.items())
    return {
        "subject": subject,
        "body": body,
        "tokens": features.tokens(subject, body),
        "vector": {str(i): v for i, v in sorted(vector.items())},
        "logit": logit,
    }


def main():
    parser = argparse.ArgumentParser(description="Write Python to Rust parity fixtures")
    parser.add_argument("--corpus-sample", type=int, default=2000)
    args = parser.parse_args()

    meta = json.loads((ROOT / "models" / "sanct-spam.json").read_text())
    weights = load_weights(meta)
    bias = meta["bias"]

    FIXTURES.mkdir(parents=True, exist_ok=True)
    edge = [case(s, b, weights, bias) for s, b in EDGE_CASES]
    (FIXTURES / "parity.json").write_text(
        json.dumps({"weights_sha256": meta["weights_sha256"], "cases": edge}, ensure_ascii=False)
    )
    (FIXTURES / "unicode.json").write_text(json.dumps(unicode_tables(), ensure_ascii=False))

    if args.corpus_sample:
        emails, _ = datasets.load()
        random.seed(7)
        sample = random.sample([e for e in emails if e.split == "test"], args.corpus_sample)
        corpus = [case(e.subject, e.body, weights, bias) for e in sample]
        out = ROOT / "data" / "parity_corpus.json"
        out.write_text(json.dumps({"weights_sha256": meta["weights_sha256"], "cases": corpus}, ensure_ascii=False))
        print(f"wrote {len(corpus)} corpus cases to {out}")
    print(f"wrote {len(edge)} edge cases and unicode tables to {FIXTURES}")


if __name__ == "__main__":
    main()
