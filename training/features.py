import math
import re
import unicodedata
import zlib

FEATURE_VERSION = 2
DIM_BITS = 20
DIM = 1 << DIM_BITS
MASK = DIM - 1

MAX_SUBJECT_CHARS = 512
MAX_BODY_CHARS = 20_000
MAX_CHAR_GRAM_CHARS = 1_500
CHAR_GRAM = 4
SNIPPET_CHARS = 200

URL_RE = re.compile(r"(?i:https?://|www\.)[^\x00-\x20\x7f<>\"'()\[\]{}]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
TAG_RE = re.compile(r"<[ \t\r\n]*/?[ \t\r\n]*[A-Za-z][^>]{0,500}>")
ENTITY_RE = re.compile(r"&(?i:nbsp|amp|lt|gt|quot|#[0-9]{1,6});")
NUM_RE = re.compile(r"[0-9]+")
IP_HOST_RE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
HOST_END_RE = re.compile(r"[/?#:]")
ZERO_WIDTH = frozenset("​‌‍⁠﻿­")
MONEY_CHARS = frozenset("$€£¥₿")

_word_char_cache = {}


def is_word_char(c):
    cached = _word_char_cache.get(c)
    if cached is None:
        cached = unicodedata.category(c)[0] in "LN"
        _word_char_cache[c] = cached
    return cached


def is_letter(c):
    return unicodedata.category(c)[0] == "L"


def is_upper(c):
    return unicodedata.category(c) == "Lu"


def _url_host(url):
    rest = url.split("://", 1)[1] if "://" in url else url
    host = HOST_END_RE.split(rest, maxsplit=1)[0].lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _prepare(text, limit):
    text = unicodedata.normalize("NFKC", text[: limit * 2])[:limit]
    stripped = "".join(c for c in text if c not in ZERO_WIDTH)
    return stripped, len(stripped) != len(text)


def _clean(text, meta):
    url_count = 0
    tlds = set()
    has_ip_url = False

    def replace_url(match):
        nonlocal url_count, has_ip_url
        url_count += 1
        host = _url_host(match.group())
        if IP_HOST_RE.fullmatch(host):
            has_ip_url = True
            return " xurlx xipurlx "
        if "." in host:
            tlds.add(host.rsplit(".", 1)[1][:12])
        return f" xurlx {host.replace('.', ' ').replace('-', ' ')} "

    text, tag_count = TAG_RE.subn(" ", text)
    text = ENTITY_RE.sub(" ", text)
    text = URL_RE.sub(replace_url, text)
    text = EMAIL_RE.sub(" xemailx ", text)

    if tag_count:
        meta.append("m:html")
    meta.append(f"m:url:{min(url_count, 5)}")
    if has_ip_url:
        meta.append("m:urlip")
    for tld in sorted(tlds):
        meta.append(f"m:tld:{tld}")
    return text


def _shape_numbers(match):
    return "9" * min(len(match.group()), 6)


def words(text):
    text = NUM_RE.sub(_shape_numbers, text.lower())
    result = []
    current = []
    joined = False
    n = len(text)
    for i, c in enumerate(text):
        if is_word_char(c):
            current.append(c)
        elif c == "'" and current and not joined and i + 1 < n and is_word_char(text[i + 1]):
            current.append(c)
            joined = True
        else:
            if current:
                result.append("".join(current))
                current = []
            joined = False
    if current:
        result.append("".join(current))
    return result


def _char_grams(tokens, prefix):
    stream = " " + " ".join(tokens)[:MAX_CHAR_GRAM_CHARS] + " "
    return [prefix + stream[i : i + CHAR_GRAM] for i in range(len(stream) - CHAR_GRAM + 1)]


def _bigrams(tokens, prefix):
    return [f"{prefix}{a} {b}" for a, b in zip(tokens, tokens[1:])]


def tokens(subject, body):
    subject, subject_zw = _prepare(subject or "", MAX_SUBJECT_CHARS)
    body, body_zw = _prepare(body or "", MAX_BODY_CHARS)
    meta = []

    letters = 0
    upper = 0
    money = 0
    non_ascii = 0
    for c in body:
        if is_letter(c):
            letters += 1
            if is_upper(c):
                upper += 1
        if c in MONEY_CHARS:
            money += 1
        if ord(c) > 127:
            non_ascii += 1

    meta.append(f"m:len:{min((len(body) + 1).bit_length() - 1, 16)}")
    meta.append(f"m:caps:{min(upper * 10 // letters, 10) if letters else 0}")
    meta.append(f"m:excl:{min(body.count('!') + subject.count('!'), 5)}")
    meta.append(f"m:money:{min(money, 3)}")
    meta.append(f"m:nonascii:{min(non_ascii * 5 // len(body), 5) if body else 0}")
    if subject_zw or body_zw:
        meta.append("m:zw")

    subject_letters = [c for c in subject if is_letter(c)]
    if not any(is_word_char(c) for c in subject):
        meta.append("m:subj_empty")
    elif len(subject_letters) >= 4 and all(is_upper(c) for c in subject_letters):
        meta.append("m:subj_caps")

    subject_words = words(_clean(subject, meta))
    body_words = words(_clean(body, meta))

    return [
        meta,
        ["s:" + w for w in subject_words] + _bigrams(subject_words, "s2:"),
        _char_grams(subject_words, "sc:") if subject_words else [],
        ["w:" + w for w in body_words] + _bigrams(body_words, "w2:"),
        _char_grams(body_words, "c:") if body_words else [],
    ]


def vectorize(subject, body):
    vector = {}
    for group in tokens(subject, body):
        if not group:
            continue
        counts = {}
        for token in group:
            h = zlib.crc32(token.encode("utf-8"))
            index = h & MASK
            sign = 1.0 if h & 0x80000000 else -1.0
            counts[index] = counts.get(index, 0.0) + sign
        scaled = {
            i: math.copysign(1.0 + math.log(abs(v)), v) for i, v in counts.items() if v != 0.0
        }
        norm = math.sqrt(sum(v * v for v in scaled.values()))
        if norm == 0.0:
            continue
        for i, v in scaled.items():
            vector[i] = vector.get(i, 0.0) + v / norm
    return vector


def snippet_view(subject, body):
    body = body or ""
    if body.strip():
        return "", body[:SNIPPET_CHARS]
    return "", (subject or "")[:SNIPPET_CHARS]
