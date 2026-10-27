use std::collections::{BTreeSet, HashMap};

use regex::{Captures, NoExpand, Regex, RegexBuilder};
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;

pub const FEATURE_VERSION: u32 = 2;
pub const DIM_BITS: u32 = 20;
pub const DIM: usize = 1 << DIM_BITS;
const MASK: u32 = (1 << DIM_BITS) - 1;
const SIGN_BIT: u32 = 0x8000_0000;

const MAX_SUBJECT_CHARS: usize = 512;
const MAX_BODY_CHARS: usize = 20_000;
const MAX_CHAR_GRAM_CHARS: usize = 1_500;
const CHAR_GRAM: usize = 4;

const ZERO_WIDTH: [char; 6] = [
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}', '\u{00ad}',
];
const MONEY: [char; 5] = ['$', '€', '£', '¥', '₿'];

pub type Groups = [Vec<String>; 5];

pub fn is_word_char(c: char) -> bool {
    is_letter(c)
        || matches!(
            get_general_category(c),
            GeneralCategory::DecimalNumber
                | GeneralCategory::LetterNumber
                | GeneralCategory::OtherNumber
        )
}

pub fn is_letter(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::UppercaseLetter
            | GeneralCategory::LowercaseLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter
    )
}

pub fn is_upper(c: char) -> bool {
    get_general_category(c) == GeneralCategory::UppercaseLetter
}

fn prepare(text: &str, limit: usize) -> (String, bool) {
    let head = match text.char_indices().nth(limit * 2) {
        Some((end, _)) => &text[..end],
        None => text,
    };
    let mut out = String::with_capacity(head.len());
    let mut removed = false;
    for c in head.nfkc().take(limit) {
        if ZERO_WIDTH.contains(&c) {
            removed = true;
        } else {
            out.push(c);
        }
    }
    (out, removed)
}

fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = rest.find(['/', '?', '#', ':']).unwrap_or(rest.len());
    let host = rest[..end].to_lowercase();
    let host = host.trim_end_matches('.');
    host.strip_prefix("www.").unwrap_or(host).to_string()
}

fn bigrams(words: &[String], prefix: &str) -> Vec<String> {
    words
        .windows(2)
        .map(|pair| format!("{prefix}{} {}", pair[0], pair[1]))
        .collect()
}

fn char_grams(words: &[String], prefix: &str) -> Vec<String> {
    if words.is_empty() {
        return Vec::new();
    }
    let joined = words.join(" ");
    let mut stream = Vec::with_capacity(MAX_CHAR_GRAM_CHARS + 2);
    stream.push(' ');
    stream.extend(joined.chars().take(MAX_CHAR_GRAM_CHARS));
    stream.push(' ');
    stream
        .windows(CHAR_GRAM)
        .map(|gram| {
            let mut token = String::with_capacity(prefix.len() + CHAR_GRAM * 4);
            token.push_str(prefix);
            token.extend(gram);
            token
        })
        .collect()
}

pub struct Extractor {
    url: Regex,
    email: Regex,
    tag: Regex,
    entity: Regex,
    number: Regex,
    ip_host: Regex,
}

impl Extractor {
    pub fn new() -> Result<Self, regex::Error> {
        let build = |pattern: &str| RegexBuilder::new(pattern).size_limit(64 << 20).build();
        Ok(Self {
            url: build(r#"(?i:https?://|www\.)[^\x00-\x20\x7f<>"'()\[\]{}]+"#)?,
            email: build(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")?,
            tag: build(r"<[ \t\r\n]*/?[ \t\r\n]*[A-Za-z][^>]{0,500}>")?,
            entity: build(r"&(?i:nbsp|amp|lt|gt|quot|#[0-9]{1,6});")?,
            number: build(r"[0-9]+")?,
            ip_host: build(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")?,
        })
    }

    fn clean(&self, text: &str, meta: &mut Vec<String>) -> String {
        let mut tag_count = 0usize;
        let text = self.tag.replace_all(text, |_: &Captures| {
            tag_count += 1;
            " "
        });
        let text = self.entity.replace_all(&text, NoExpand(" "));

        let mut url_count = 0usize;
        let mut has_ip_url = false;
        let mut tlds = BTreeSet::new();
        let text = self.url.replace_all(&text, |caps: &Captures| {
            url_count += 1;
            let host = url_host(&caps[0]);
            if self.ip_host.is_match(&host) {
                has_ip_url = true;
                return " xurlx xipurlx ".to_string();
            }
            if let Some((_, tld)) = host.rsplit_once('.') {
                tlds.insert(tld.chars().take(12).collect::<String>());
            }
            format!(" xurlx {} ", host.replace(['.', '-'], " "))
        });
        let text = self
            .email
            .replace_all(&text, NoExpand(" xemailx "))
            .into_owned();

        if tag_count > 0 {
            meta.push("m:html".to_string());
        }
        meta.push(format!("m:url:{}", url_count.min(5)));
        if has_ip_url {
            meta.push("m:urlip".to_string());
        }
        for tld in tlds {
            meta.push(format!("m:tld:{tld}"));
        }
        text
    }

    pub fn has_link(&self, text: &str) -> bool {
        self.url.is_match(text) || self.email.is_match(text)
    }

    pub fn words(&self, text: &str) -> Vec<String> {
        let lowered = text.to_lowercase();
        let shaped = self
            .number
            .replace_all(&lowered, |caps: &Captures| "9".repeat(caps[0].len().min(6)));
        let chars: Vec<char> = shaped.chars().collect();
        let mut words = Vec::new();
        let mut current = String::new();
        let mut joined = false;
        for (i, &c) in chars.iter().enumerate() {
            if is_word_char(c) {
                current.push(c);
            } else if c == '\''
                && !current.is_empty()
                && !joined
                && chars.get(i + 1).is_some_and(|&next| is_word_char(next))
            {
                current.push(c);
                joined = true;
            } else {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
                joined = false;
            }
        }
        if !current.is_empty() {
            words.push(current);
        }
        words
    }

    pub fn tokens(&self, subject: &str, body: &str) -> Groups {
        let (subject, subject_zw) = prepare(subject, MAX_SUBJECT_CHARS);
        let (body, body_zw) = prepare(body, MAX_BODY_CHARS);
        let mut meta = Vec::new();

        let (mut length, mut letters, mut upper, mut money, mut non_ascii, mut bangs) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        for c in body.chars() {
            length += 1;
            if is_letter(c) {
                letters += 1;
                if is_upper(c) {
                    upper += 1;
                }
            }
            if MONEY.contains(&c) {
                money += 1;
            }
            if u32::from(c) > 127 {
                non_ascii += 1;
            }
            if c == '!' {
                bangs += 1;
            }
        }
        bangs += subject.chars().filter(|&c| c == '!').count();

        let length_bits = (usize::BITS - (length + 1).leading_zeros() - 1).min(16);
        meta.push(format!("m:len:{length_bits}"));
        let caps = if letters > 0 {
            (upper * 10 / letters).min(10)
        } else {
            0
        };
        meta.push(format!("m:caps:{caps}"));
        meta.push(format!("m:excl:{}", bangs.min(5)));
        meta.push(format!("m:money:{}", money.min(3)));
        let non_ascii = if length > 0 {
            (non_ascii * 5 / length).min(5)
        } else {
            0
        };
        meta.push(format!("m:nonascii:{non_ascii}"));
        if subject_zw || body_zw {
            meta.push("m:zw".to_string());
        }

        let subject_letters: Vec<char> = subject.chars().filter(|&c| is_letter(c)).collect();
        if !subject.chars().any(is_word_char) {
            meta.push("m:subj_empty".to_string());
        } else if subject_letters.len() >= 4 && subject_letters.iter().all(|&c| is_upper(c)) {
            meta.push("m:subj_caps".to_string());
        }

        let subject_words = self.words(&self.clean(&subject, &mut meta));
        let body_words = self.words(&self.clean(&body, &mut meta));

        let mut subject_tokens: Vec<String> =
            subject_words.iter().map(|w| format!("s:{w}")).collect();
        subject_tokens.extend(bigrams(&subject_words, "s2:"));
        let mut body_tokens: Vec<String> = body_words.iter().map(|w| format!("w:{w}")).collect();
        body_tokens.extend(bigrams(&body_words, "w2:"));

        [
            meta,
            subject_tokens,
            char_grams(&subject_words, "sc:"),
            body_tokens,
            char_grams(&body_words, "c:"),
        ]
    }

    pub fn vectorize(&self, subject: &str, body: &str) -> HashMap<u32, f64> {
        let mut vector = HashMap::new();
        for group in self.tokens(subject, body) {
            if group.is_empty() {
                continue;
            }
            let mut counts: HashMap<u32, f64> = HashMap::with_capacity(group.len());
            for token in &group {
                let hash = crc32fast::hash(token.as_bytes());
                let sign = if hash & SIGN_BIT != 0 { 1.0 } else { -1.0 };
                *counts.entry(hash & MASK).or_insert(0.0) += sign;
            }
            let scaled: Vec<(u32, f64)> = counts
                .into_iter()
                .filter(|&(_, v)| v != 0.0)
                .map(|(i, v)| (i, (1.0 + v.abs().ln()).copysign(v)))
                .collect();
            let norm = scaled.iter().map(|&(_, v)| v * v).sum::<f64>().sqrt();
            if norm == 0.0 {
                continue;
            }
            for (i, v) in scaled {
                *vector.entry(i).or_insert(0.0) += v / norm;
            }
        }
        vector
    }
}
