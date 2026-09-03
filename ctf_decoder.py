#!/usr/bin/env python3
"""
================================================================================
 CTF AUTO-DECODER -- multi-layer encoding / cipher detective
================================================================================
Paste in a mystery string and this tool automatically detects and peels back
every layer of encoding/encryption until it finds human-readable plaintext or
a flag -- e.g. Base32 -> Base64 -> single-byte XOR -> plaintext, all chained
automatically.

Handles: Base16/32/58/64/85, binary, octal, decimal byte-lists, URL-encoding,
Morse code, ROT13/Caesar (brute-forced), Atbash, single-byte XOR (brute-
forced), repeating-key XOR (auto key-length + key recovery), Vigenere (auto
key recovery), gzip/zlib/bz2/lzma/raw-deflate decompression, and reversed
strings -- chained to arbitrary depth.

USAGE
-----
    python3 ctf_decoder.py                  interactive mode (paste input)
    python3 ctf_decoder.py "ZmxhZ3t9fQ=="   decode a string directly
    python3 ctf_decoder.py -f mystery.txt   decode the contents of a file
    python3 ctf_decoder.py --manual         jump straight to the manual toolkit
    python3 ctf_decoder.py -v "..."         verbose: show every path explored

No third-party dependencies -- standard library only. Requires Python 3.7+.
================================================================================
"""

import argparse
import base64
import binascii
import bz2
import codecs
import gzip
import lzma
import re
import string
import sys
import time
import zlib
from collections import Counter
from urllib.parse import unquote_to_bytes, quote_from_bytes

# ============================================================================
#  0. TERMINAL COLOURS  (auto-disabled when not attached to a TTY)
# ============================================================================

class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


def _disable_colour_if_needed():
    if not sys.stdout.isatty():
        for attr in ('HEADER', 'BLUE', 'CYAN', 'GREEN', 'YELLOW', 'RED', 'BOLD', 'DIM', 'END'):
            setattr(C, attr, '')


# ============================================================================
#  1. SCORING / "DOES THIS LOOK LIKE PLAINTEXT" HELPERS
# ============================================================================

# Relative frequency (%) of each letter and the space character in typical
# English text. Used for chi-squared goodness-of-fit scoring when brute
# forcing Caesar shifts / XOR keys.
ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702, 'f': 2.228,
    'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
    'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929, 'q': 0.095, 'r': 5.987,
    's': 6.327, 't': 9.056, 'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
    'y': 1.974, 'z': 0.074, ' ': 13.000,
}

# Visible ASCII + newline ONLY -- deliberately stricter than Python's
# string.printable, which also counts \r, \t, \x0b, \x0c as "printable".
# Those control characters are essentially never present in genuine flag or
# English text, but frequently appear in wrongly-XORed garbage (a huge chunk
# of the 0-255 byte space is control codes); counting them as printable was
# letting garbage decodes slip past the "does this look like real text"
# filter. This set is used everywhere "looks like text" is judged.
_GOOD_CHARS = frozenset(chr(c) for c in range(0x20, 0x7F)) | {'\n'}


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch in _GOOD_CHARS)
    return good / len(text)

COMMON_WORDS = set("""
the be to of and a in that have i it for not on with he as you do at this
but his by from they we say her she or an will my one all would there their
what so up out if about who get which go me when make can like time no just
him know take people into year your good some could them see other than then
now look only come its over think also back after use two how our work first
well way even new want because any these give day most us flag ctf secret
key password congrats congratulations welcome here challenge decrypt decode
cipher encrypted hidden hint solve found correct success
""".split())

# Well-known CTF flag wrapper formats. A match here is HIGH CONFIDENCE and is
# used to stop the search -- these prefixes are specific enough that they
# essentially never appear by coincidence in undecoded ciphertext.
FLAG_PATTERNS = [
    re.compile(r'\bflag\{[^{}]{1,300}\}', re.IGNORECASE),
    re.compile(r'\bctf\{[^{}]{1,300}\}', re.IGNORECASE),
    re.compile(r'\bpico[cC][tT][fF]\{[^{}]{1,300}\}'),
    re.compile(r'\bHTB\{[^{}]{1,300}\}'),
    re.compile(r'\bhackthebox\{[^{}]{1,300}\}', re.IGNORECASE),
]

# Generic "identifier{...}" shape, for custom/unknown competition prefixes.
# IMPORTANT: this is LOW CONFIDENCE and must never be used to halt the BFS --
# classical ciphers (Caesar/Atbash/ROT13) don't touch '{', '}', '_' or digits,
# so raw ciphertext of "flag{...}" keeps that exact shape and would otherwise
# be mistaken for a solved flag before any real decoding happens. It's only
# used as a minor scoring signal / last-resort fallback candidate.
GENERIC_FLAG_PATTERN = re.compile(r'\b[A-Za-z][A-Za-z0-9_]{1,19}\{[\w \-.,!?\'":;/]{1,200}\}')


def as_text(data: bytes) -> str:
    """Best-effort 1:1 text view of bytes for regex/pattern matching. Never raises."""
    return data.decode('latin1')


def strip_ws(s: str) -> str:
    return re.sub(r'\s+', '', s)


def contains_flag(text: str):
    """High-confidence match against a well-known flag wrapper. Safe to halt search on."""
    for pat in FLAG_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


def contains_generic_flag_shape(text: str):
    """Low-confidence 'identifier{...}' shape match. Scoring signal ONLY -- never halts search."""
    m = GENERIC_FLAG_PATTERN.search(text)
    return m.group(0) if m else None


def chi_squared(text_lower: str) -> float:
    """
    Lower = closer to expected English letter-frequency distribution.
    Only a-z and space are considered; other characters (digits, braces,
    underscores -- all extremely common in flag-style text like
    "flag{some_words_here}") are excluded from both the observed and
    expected counts. Including them would inflate n without those
    characters ever being able to satisfy a letter bucket, systematically
    distorting the statistic against exactly the kind of text this tool
    spends most of its time scoring.
    """
    relevant = [ch for ch in text_lower if ch in ENGLISH_FREQ]
    n = len(relevant)
    if n == 0:
        return 1e9
    counts = Counter(relevant)
    score = 0.0
    for ch, expected_pct in ENGLISH_FREQ.items():
        observed = counts.get(ch, 0)
        expected = expected_pct / 100.0 * n
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def score_text(data: bytes) -> float:
    """
    Higher = more likely to be genuine English plaintext / a flag.
    Combines printable ratio, chi-squared letter-frequency fit, common-word
    hits, and an explicit flag-pattern bonus. Used to rank BFS results and
    to pick a *final* winner among a small number of candidates. Expensive
    (regex flag-matching + word tokenization) -- NOT for hot search loops.
    """
    if not data:
        return -1e9
    text = as_text(data)
    printable_ratio = _printable_ratio(text)
    if printable_ratio < 0.90:
        return -1000.0 * (1.0 - printable_ratio)

    lower = text.lower()
    letters = [ch for ch in lower if ch.isalpha()]
    letter_ratio = len(letters) / len(lower)
    chi = chi_squared(lower) if letters else 500.0
    # Chi-squared is computed only over a-z+space, so a decode that's mostly
    # digits/punctuation with just a few letters can make it degenerate
    # (tiny sample size) and score deceptively well. Penalize low letter
    # density directly so that can't happen.
    low_letter_penalty = max(0.0, 0.30 - letter_ratio) * 300.0

    words = re.findall(r'[a-z]+', lower)
    common_hits = sum(1 for w in words if w in COMMON_WORDS)

    if contains_flag(text):
        flag_bonus = 800.0
    elif contains_generic_flag_shape(text):
        flag_bonus = 150.0
    else:
        flag_bonus = 0.0
    space_bonus = 10.0 if ' ' in text.strip() else 0.0

    return (flag_bonus + common_hits * 15.0 + printable_ratio * 20.0 + space_bonus
            - chi * 0.5 - low_letter_penalty)


def quick_score(data: bytes) -> float:
    """
    Cheap proxy for score_text: printable ratio + chi-squared only, no regex
    flag-matching or word tokenization. Used inside hot brute-force/hill-climb
    search loops (called thousands of times) where the full scorer's regex
    overhead would dominate runtime. The final candidate from each search is
    always re-ranked with the real score_text before being reported.
    """
    if not data:
        return -1e9
    text = as_text(data)
    ratio = _printable_ratio(text)
    if ratio < 0.90:
        return -1000.0 * (1.0 - ratio)
    lower = text.lower()
    letter_ratio = sum(1 for ch in lower if ch.isalpha()) / len(lower)
    chi = chi_squared(lower) if letter_ratio > 0 else 500.0
    low_letter_penalty = max(0.0, 0.30 - letter_ratio) * 300.0
    return ratio * 20.0 - chi * 0.5 - low_letter_penalty


def word_aware_score(data: bytes) -> float:
    """
    Hill-climb objective for repeating-XOR/Vigenere key recovery: like
    quick_score (cheap -- no flag-pattern regex) but also rewards
    recognizable English words, which quick_score's pure aggregate
    letter-frequency statistic can't see (it can't tell that changing one
    key byte/letter just turned a real word into garbage, since the overall
    distribution barely moves).

    Deliberately excludes score_text's flag-pattern bonus: rewarding a
    hill-climb step for producing a flag-SHAPED substring creates a
    perverse incentive to corrupt the rest of the key just to manufacture
    that shape. In testing this produced exactly that failure mode -- the
    search converged on a wrong key because it accidentally spelled
    "flag{i}" instead of the real flag. Word matches are a much harder
    coincidence to fake, so they stay.
    """
    if not data:
        return -1e9
    text = as_text(data)
    ratio = _printable_ratio(text)
    if ratio < 0.90:
        return -1000.0 * (1.0 - ratio)
    lower = text.lower()
    letter_ratio = sum(1 for ch in lower if ch.isalpha()) / len(lower)
    chi = chi_squared(lower) if letter_ratio > 0 else 500.0
    low_letter_penalty = max(0.0, 0.30 - letter_ratio) * 300.0
    words = re.findall(r'[a-z]+', lower)
    common_hits = sum(1 for w in words if w in COMMON_WORDS)
    space_bonus = 5.0 if ' ' in text.strip() else 0.0
    return ratio * 20.0 + common_hits * 15.0 + space_bonus - chi * 0.5 - low_letter_penalty


# File-type "magic byte" signatures, used purely to *identify* binary output
# that isn't meant to be read as text (e.g. a flag hidden inside a PNG).
MAGIC_SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', 'PNG image'),
    (b'\xff\xd8\xff', 'JPEG image'),
    (b'GIF8', 'GIF image'),
    (b'PK\x03\x04', 'ZIP archive'),
    (b'%PDF', 'PDF document'),
    (b'\x7fELF', 'ELF executable'),
    (b'BM', 'BMP image'),
    (b'\x1f\x8b', 'GZIP archive'),
    (b'BZh', 'BZIP2 archive'),
    (b'7z\xbc\xaf\x27\x1c', '7-Zip archive'),
    (b'Rar!\x1a\x07', 'RAR archive'),
    (b'\x00\x00\x00\x18ftyp', 'MP4 video'),
    (b'ID3', 'MP3 audio'),
]


def identify_file_type(data: bytes):
    for sig, name in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return name
    return None


def detect_hash(text: str):
    """Hashes are one-way -- we can't decode them, only flag that they ARE one."""
    t = text.strip()
    if not re.fullmatch(r'[0-9a-fA-F]+', t):
        return None
    lengths = {32: 'MD5 / NTLM', 40: 'SHA-1', 56: 'SHA-224', 64: 'SHA-256',
               96: 'SHA-384', 128: 'SHA-512'}
    return lengths.get(len(t))


# ============================================================================
#  2. DECODERS
#     Each "simple" decoder: bytes -> bytes | None  (None = not applicable)
#     Each "smart" decoder (brute-force ones): bytes -> [(bytes, label), ...]
#       returning its own top candidates instead of forcing the BFS engine
#       to branch over an entire keyspace.
# ============================================================================

# ---- Base encodings --------------------------------------------------------

def dec_hex(data: bytes):
    text = as_text(data)
    cleaned = re.sub(r'0[xX]|\\x|\\u00|[,\s]', '', text)
    if not cleaned or not re.fullmatch(r'[0-9a-fA-F]+', cleaned):
        return None
    if len(cleaned) % 2 != 0:
        return None
    try:
        return bytes.fromhex(cleaned)
    except Exception:
        return None


def dec_base64_std(data: bytes):
    text = strip_ws(as_text(data))
    if len(text) < 4 or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', text):
        return None
    padded = text + '=' * (-len(text) % 4)
    try:
        result = base64.b64decode(padded, validate=False)
        return result if result else None
    except Exception:
        return None


def dec_base64_urlsafe(data: bytes):
    text = strip_ws(as_text(data))
    if len(text) < 4 or not re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', text):
        return None
    if not re.search(r'[_-]', text):
        return None  # no urlsafe-specific chars -> would duplicate dec_base64_std
    padded = text + '=' * (-len(text) % 4)
    try:
        result = base64.urlsafe_b64decode(padded)
        return result if result else None
    except Exception:
        return None


def dec_base32(data: bytes):
    text = strip_ws(as_text(data)).upper()
    if len(text) < 8 or not re.fullmatch(r'[A-Z2-7]+=*', text):
        return None
    padded = text + '=' * (-len(text) % 8)
    try:
        result = base64.b32decode(padded)
        return result if result else None
    except Exception:
        return None


def dec_base85(data: bytes):
    text = strip_ws(as_text(data))
    if len(text) < 5 or not re.fullmatch(r'[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+', text):
        return None
    try:
        result = base64.b85decode(text)
        return result if result else None
    except Exception:
        return None


def dec_ascii85(data: bytes):
    text = strip_ws(as_text(data))
    if text.startswith('<~') and text.endswith('~>'):
        text = text[2:-2]
    if len(text) < 5:
        return None
    try:
        result = base64.a85decode(text)
        return result if result else None
    except Exception:
        return None


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def dec_base58(data: bytes):
    text = strip_ws(as_text(data))
    if len(text) < 4 or not re.fullmatch(r'[%s]+' % re.escape(_B58_ALPHABET), text):
        return None
    # Require at least one letter to avoid colliding with plain decimal digit strings
    if not re.search(r'[A-Za-z]', text):
        return None
    try:
        num = 0
        for ch in text:
            num = num * 58 + _B58_ALPHABET.index(ch)
        body = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
        n_pad = len(text) - len(text.lstrip('1'))
        result = b'\x00' * n_pad + body
        return result if result else None
    except Exception:
        return None


def dec_binary(data: bytes):
    text = strip_ws(as_text(data))
    if len(text) < 8 or not re.fullmatch(r'[01]+', text):
        return None
    if len(text) % 8 != 0:
        return None
    try:
        n = int(text, 2)
        result = n.to_bytes(len(text) // 8, 'big')
        return result if result else None
    except Exception:
        return None


def dec_octal(data: bytes):
    text = as_text(data).strip()
    parts = re.split(r'[,\s]+', text)
    parts = [p for p in parts if p]
    if len(parts) < 2 or not all(re.fullmatch(r'[0-7]{1,4}', p) for p in parts):
        return None
    try:
        vals = [int(p, 8) for p in parts]
        if all(0 <= v <= 255 for v in vals):
            return bytes(vals)
    except Exception:
        pass
    return None


def dec_decimal(data: bytes):
    text = as_text(data).strip()
    parts = re.split(r'[,\s]+', text)
    parts = [p for p in parts if p]
    if len(parts) < 2 or not all(re.fullmatch(r'\d{1,3}', p) for p in parts):
        return None
    try:
        vals = [int(p) for p in parts]
        if all(0 <= v <= 255 for v in vals):
            return bytes(vals)
    except Exception:
        pass
    return None


def dec_url(data: bytes):
    text = as_text(data)
    if '%' not in text or not re.search(r'%[0-9a-fA-F]{2}', text):
        return None
    try:
        result = unquote_to_bytes(text)
        return result if result != data else None
    except Exception:
        return None


_MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.',
}
_REVERSE_MORSE = {v: k for k, v in _MORSE.items()}


def dec_morse(data: bytes):
    text = as_text(data).strip()
    if not text or not re.fullmatch(r'[.\-/ \t\n]+', text):
        return None
    words = re.split(r'\s*/\s*', text)
    out_words = []
    for w in words:
        letters = w.strip().split()
        decoded = ''.join(_REVERSE_MORSE.get(tok, '') for tok in letters if tok)
        if decoded:
            out_words.append(decoded)
    result = ' '.join(out_words)
    return result.encode('utf-8') if result else None


def dec_reverse(data: bytes):
    if len(data) < 2:
        return None
    return data[::-1]


# ---- Classical ciphers ------------------------------------------------------

def _mostly_alpha(text: str) -> bool:
    letters = sum(1 for c in text if c.isalpha())
    return len(text) > 0 and letters / len(text) >= 0.6


def caesar_shift_text(text: str, shift: int) -> str:
    out = []
    for c in text:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - 97 - shift) % 26 + 97))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
        else:
            out.append(c)
    return ''.join(out)


def dec_caesar_bruteforce(data: bytes):
    """Smart decoder: tries all 25 shifts, returns the top-3 by score."""
    text = as_text(data)
    if not _mostly_alpha(text) or len(text) < 3:
        return None
    scored = []
    for shift in range(1, 26):
        shifted = caesar_shift_text(text, shift)
        s = score_text(shifted.encode('latin1'))
        label = 'ROT13' if shift == 13 else f'Caesar cipher (shift={shift})'
        scored.append((s, shifted.encode('latin1'), label))
    scored.sort(key=lambda x: -x[0])
    return [(b, label) for s, b, label in scored[:3]]


def dec_atbash(data: bytes):
    text = as_text(data)
    if not _mostly_alpha(text) or len(text) < 2:
        return None
    out = []
    for c in text:
        if 'a' <= c <= 'z':
            out.append(chr(122 - (ord(c) - 97)))
        elif 'A' <= c <= 'Z':
            out.append(chr(90 - (ord(c) - 65)))
        else:
            out.append(c)
    result = ''.join(out)
    return result.encode('latin1') if result != text else None


def vigenere_decode_text(text: str, key: str) -> str:
    out = []
    ki = 0
    key = key.lower()
    if not key:
        return text
    for c in text:
        if 'a' <= c <= 'z':
            shift = ord(key[ki % len(key)]) - 97
            out.append(chr((ord(c) - 97 - shift) % 26 + 97))
            ki += 1
        elif 'A' <= c <= 'Z':
            shift = ord(key[ki % len(key)]) - 97
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)


def _index_of_coincidence(letters: str) -> float:
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def dec_vigenere_crack(data: bytes):
    """
    Smart decoder: guesses candidate Vigenere key lengths via Index of
    Coincidence, gets an initial per-column Caesar-shift guess via
    chi-squared, then hill-climbs each key letter against the FULL decoded
    text's score (word-aware, not just per-column letter frequency). Short
    ciphertexts give noisy per-column statistics, so the holistic re-check
    against real word matches catches and fixes individual wrong letters
    that chi-squared alone would miss.
    """
    text = as_text(data)
    letters_only = re.sub(r'[^a-zA-Z]', '', text)
    if len(letters_only) < 40 or not _mostly_alpha(text):
        return None

    ioc_ranked = []
    for keylen in range(2, min(21, len(letters_only) // 8 + 1)):
        cols = [letters_only[i::keylen].lower() for i in range(keylen)]
        avg_ioc = sum(_index_of_coincidence(c) for c in cols) / keylen
        ioc_ranked.append((keylen, abs(avg_ioc - 0.067)))  # 0.067 ~= English IOC
    ioc_ranked.sort(key=lambda x: x[1])
    keylen_candidates = [k for k, gap in ioc_ranked[:3] if gap < 0.045]
    if not keylen_candidates:
        return None  # not confident this is Vigenere at all

    results = []
    for keylen in keylen_candidates:
        key_shifts = []
        for i in range(keylen):
            col = letters_only[i::keylen].lower()
            best_shift, best_chi = 0, 1e9
            for shift in range(26):
                chi = chi_squared(caesar_shift_text(col, shift))
                if chi < best_chi:
                    best_chi, best_shift = chi, shift
            key_shifts.append(best_shift)

        def decode_with(shifts):
            key = ''.join(chr(97 + s) for s in shifts)
            return vigenere_decode_text(text, key)

        # Bail out early if even the initial per-column guess looks nothing
        # like text -- not worth hill-climbing what is probably noise.
        if quick_score(decode_with(key_shifts).encode('latin1')) < -50:
            continue

        # Hill-climb against the FULL score_text (word-aware), not the cheap
        # quick_score. quick_score is a pure aggregate letter-frequency
        # statistic -- it can't tell that changing one key letter just
        # turned a real word into garbage, since the overall letter
        # distribution barely moves. That blindness let hill-climbing
        # actively *corrupt* an already-correct key in testing. score_text's
        # word-match + flag-pattern bonus is position-aware enough to avoid
        # that, and the keyspace here (<=20 positions x 26 letters x <=3
        # passes) is small enough that the extra cost is negligible.
        improved, iters = True, 0
        while improved and iters < 3:
            improved, iters = False, iters + 1
            for pos in range(keylen):
                best_score = word_aware_score(decode_with(key_shifts).encode('latin1'))
                best_shift = key_shifts[pos]
                for cand in range(26):
                    if cand == key_shifts[pos]:
                        continue
                    trial = list(key_shifts)
                    trial[pos] = cand
                    s = word_aware_score(decode_with(trial).encode('latin1'))
                    if s > best_score:
                        best_score, best_shift, improved = s, cand, True
                key_shifts[pos] = best_shift

        key = ''.join(chr(97 + s) for s in key_shifts)
        decoded = decode_with(key_shifts)
        results.append((score_text(decoded.encode('latin1')), decoded.encode('latin1'),
                         f"Vigenere cipher (recovered key='{key}')"))

    results.sort(key=lambda x: -x[0])
    top = [(b, label) for s, b, label in results[:2]]
    return top if top else None


# ---- XOR ---------------------------------------------------------------

def dec_xor_single_byte(data: bytes):
    """Smart decoder: brute-forces all 256 single-byte XOR keys, top-3 by score."""
    if len(data) < 2:
        return None
    scored = []
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        s = score_text(decoded)
        scored.append((s, decoded, f'XOR single-byte (key=0x{key:02x})'))
    scored.sort(key=lambda x: -x[0])
    top = [(b, label) for s, b, label in scored[:3] if s > -500]
    return top if top else None


def _hamming_distance(b1: bytes, b2: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))


def _guess_xor_keylengths(data: bytes, max_len=16, top_n=3):
    """
    Guess candidate repeating-XOR key lengths via normalised Hamming distance
    (Cryptopals-style). Uses as many non-overlapping chunks as available
    (up to 8) rather than a fixed 4, since short ciphertexts need every bit
    of statistical signal they can get.

    The raw ranking is then expanded in both directions, since a length
    that evenly divides the true key length also shows partial cancellation
    (a real detected-6 will often show up ranked alongside its divisors 2
    and 3 -- sometimes *instead* of 6 itself, if the plaintext has its own
    short-range repetition): divisors of large candidates, and small
    multiples of small candidates, are both added. Total stays capped since
    each candidate triggers a real keyspace search downstream.
    """
    candidates = []
    max_len = min(max_len, len(data) // 4)
    for keylen in range(2, max(3, max_len)):
        num_chunks = min(8, len(data) // keylen)
        if num_chunks < 2:
            continue
        chunks = [data[i * keylen:(i + 1) * keylen] for i in range(num_chunks)]
        dist, pairs = 0.0, 0
        for i in range(len(chunks)):
            for j in range(i + 1, len(chunks)):
                dist += _hamming_distance(chunks[i], chunks[j]) / keylen
                pairs += 1
        if pairs:
            candidates.append((keylen, dist / pairs))
    candidates.sort(key=lambda x: x[1])
    top = [k for k, _ in candidates[:top_n]]

    expanded = list(top)
    for k in top:
        for mult in (2, 3):
            m = k * mult
            if m <= max_len and m not in expanded:
                expanded.append(m)
    for k in top:
        smallest_divisor = next((d for d in range(2, k) if k % d == 0), None)
        if smallest_divisor and smallest_divisor not in expanded:
            expanded.append(smallest_divisor)
    return expanded[:6]


def _xor_byte_score(col_text: str) -> float:
    """
    Lower is better. Used when brute-forcing a single XOR key byte against a
    short column of text, where we can't afford the full score_text per
    candidate (256 calls x keylen columns). Combines chi-squared letter-fit
    with two penalties chi-squared alone can't see: control/garbage
    characters, and low letter-density. The latter matters because a decode
    that's all digits/punctuation with barely any actual letters can make
    chi-squared degenerate (n close to 0 relevant chars) and score
    deceptively well just by having almost nothing to be "wrong" about.
    """
    n = len(col_text)
    if n == 0:
        return 1e9
    bad = sum(1 for ch in col_text if ch not in _GOOD_CHARS)
    letters = sum(1 for ch in col_text if ch.isalpha())
    garbage_penalty = (bad / n) * 500.0
    low_letter_penalty = max(0.0, 0.5 - letters / n) * 400.0
    return chi_squared(col_text) + garbage_penalty + low_letter_penalty


def dec_xor_repeating(data: bytes):
    """
    Smart decoder: Cryptopals-style repeating-key XOR break. Guesses
    candidate key length(s) via normalised Hamming distance, gets an initial
    per-byte key guess via chi-squared, then hill-climbs each key byte
    against the FULL decoded text's score. The per-byte chi-squared pass
    alone is noisy on short ciphertext (few bytes per column), so the
    holistic re-check catches wrong bytes that independent analysis misses.
    Only attempted on reasonably long binary blobs, and depth-limited by the
    BFS engine since this does real work.
    """
    if len(data) < 24:
        return None
    keylens = _guess_xor_keylengths(data)
    if not keylens:
        return None

    def decode_with(key_bytes):
        return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

    results = []
    for keylen in keylens:
        key = bytearray(keylen)
        for i in range(keylen):
            block = data[i::keylen]
            best_byte, best_chi = 0, 1e9
            for k in range(256):
                col = bytes(b ^ k for b in block)
                chi = _xor_byte_score(as_text(col).lower())
                if chi < best_chi:
                    best_chi, best_byte = chi, k
            key[i] = best_byte

        # Bail out early if the initial per-byte guess looks nothing like
        # text -- not worth hill-climbing what is probably the wrong keylen.
        if quick_score(decode_with(bytes(key))) < -20:
            continue

        # Hill-climb against the FULL score_text (word-aware), not the cheap
        # quick_score -- see dec_vigenere_crack for why: quick_score is a
        # pure aggregate letter-frequency statistic that can't tell a
        # corrupted word from a fine one, and was observed to actively
        # corrupt an already-correct key during testing.
        improved, iters = True, 0
        while improved and iters < 1:
            improved, iters = False, iters + 1
            for pos in range(keylen):
                best_score = word_aware_score(decode_with(bytes(key)))
                best_byte = key[pos]
                for cand in range(256):
                    if cand == key[pos]:
                        continue
                    trial = bytearray(key)
                    trial[pos] = cand
                    s = word_aware_score(decode_with(bytes(trial)))
                    if s > best_score:
                        best_score, best_byte, improved = s, cand, True
                key[pos] = best_byte

        key_bytes = bytes(key)
        decoded = decode_with(key_bytes)
        s = score_text(decoded)
        try:
            key_repr = key_bytes.decode('ascii')
            if not key_repr.isprintable():
                raise ValueError
            key_label = f"key='{key_repr}'"
        except Exception:
            key_label = f"key=0x{key_bytes.hex()}"
        results.append((s, decoded, f"Repeating-key XOR ({key_label}, len={keylen})"))

    results.sort(key=lambda x: -x[0])
    top = [(b, label) for s, b, label in results[:2] if s > -200]
    return top if top else None


# ---- Compression ---------------------------------------------------------

def dec_zlib(data: bytes):
    try:
        result = zlib.decompress(data)
        return result if result else None
    except Exception:
        return None


def dec_raw_deflate(data: bytes):
    try:
        result = zlib.decompressobj(wbits=-15).decompress(data)
        return result if result else None
    except Exception:
        return None


def dec_gzip(data: bytes):
    try:
        result = gzip.decompress(data)
        return result if result else None
    except Exception:
        return None


def dec_bz2(data: bytes):
    try:
        result = bz2.decompress(data)
        return result if result else None
    except Exception:
        return None


def dec_lzma(data: bytes):
    try:
        result = lzma.decompress(data)
        return result if result else None
    except Exception:
        return None


# ============================================================================
#  3. DECODER REGISTRY
#     'simple'  -> function returns bytes|None
#     'smart'   -> function returns [(bytes, label), ...] | None  (already
#                  narrowed down from a large keyspace to its best guesses)
# ============================================================================

SIMPLE_DECODERS = [
    ("Hex decode", dec_hex),
    ("Base64 decode", dec_base64_std),
    ("Base64 (URL-safe) decode", dec_base64_urlsafe),
    ("Base32 decode", dec_base32),
    ("Base85 decode", dec_base85),
    ("Ascii85 decode", dec_ascii85),
    ("Base58 decode", dec_base58),
    ("Binary decode", dec_binary),
    ("Octal decode", dec_octal),
    ("Decimal byte-list decode", dec_decimal),
    ("URL decode", dec_url),
    ("Morse code decode", dec_morse),
    ("Atbash cipher", dec_atbash),
    ("Reversed string", dec_reverse),
    ("Zlib decompress", dec_zlib),
    ("Raw-deflate decompress", dec_raw_deflate),
    ("Gzip decompress", dec_gzip),
    ("Bzip2 decompress", dec_bz2),
    ("LZMA/XZ decompress", dec_lzma),
]

# Cheap smart-decoders: run at every BFS node regardless of depth.
SMART_DECODERS_CHEAP = [
    dec_caesar_bruteforce,
    dec_xor_single_byte,
]

# Expensive smart-decoders (full keyspace/key-length search): these do real
# work (hundreds-to-thousands of scoring calls), so the BFS only runs them
# near the root. In practice a "crack the whole ciphertext" layer is almost
# always the outermost or near-outermost layer, so this trade-off costs
# little accuracy for a large speedup.
SMART_DECODERS_EXPENSIVE = [
    dec_vigenere_crack,
    dec_xor_repeating,
]
EXPENSIVE_DECODER_MAX_DEPTH = 1


# ============================================================================
#  4. BFS AUTO-SOLVE ENGINE
# ============================================================================

class SolveResult:
    __slots__ = ('bytes_val', 'chain', 'score', 'flag', 'depth')

    def __init__(self, bytes_val, chain, score, flag, depth):
        self.bytes_val = bytes_val
        self.chain = chain          # list of transform labels applied, in order
        self.score = score
        self.flag = flag            # matched flag substring, or None
        self.depth = depth


def bfs_solve(start_bytes: bytes, max_depth=6, max_nodes=1500, verbose=False, time_budget=12.0):
    """
    Breadth-first search over the space of possible decodings.
    Returns (flag_hits, leaf_candidates, nodes_explored).
      flag_hits       -- SolveResult objects where an explicit flag pattern matched
      leaf_candidates -- every node where no further decoder applied (dead ends),
                          i.e. plausible "final" results, ranked by score

    A wall-clock `time_budget` (seconds) is enforced as a hard safety net on
    top of max_nodes, so pathological input can never hang the tool -- it
    just returns its best findings so far.
    """
    start_time = time.time()
    visited = {start_bytes}
    queue = [(start_bytes, [], 0)]
    flag_hits = []
    leaf_candidates = []
    nodes_explored = 0
    timed_out = False
    soft_stop_at = None  # once a flag is found, stop soon after instead of using the full budget

    while queue:
        if nodes_explored >= max_nodes or (time.time() - start_time) > time_budget:
            timed_out = nodes_explored < len(visited)
            break
        if soft_stop_at is not None and nodes_explored >= soft_stop_at:
            break

        current, chain, depth = queue.pop(0)
        nodes_explored += 1

        text = as_text(current)
        flag = contains_flag(text)
        if flag:
            flag_hits.append(SolveResult(current, chain, score_text(current), flag, depth))
            if verbose:
                print(f"{C.GREEN}  [depth {depth}] FLAG MATCH via {' -> '.join(chain) or '(input)'}{C.END}")
            # Found a high-confidence flag. Let a small, bounded number of
            # sibling branches keep exploring (in case an equally-shallow
            # alternate path also resolves), then stop -- no need to burn
            # the full node/time budget once we're confident.
            if soft_stop_at is None:
                soft_stop_at = nodes_explored + 40
            continue

        produced_children = False
        if depth < max_depth:
            decoders_to_try = list(SIMPLE_DECODERS)
            for name, func in decoders_to_try:
                try:
                    result = func(current)
                except Exception:
                    result = None
                if result is None or result == current or result in visited:
                    continue
                visited.add(result)
                produced_children = True
                if verbose:
                    print(f"{C.DIM}  [depth {depth}] {' -> '.join(chain + [name])}{C.END}")
                queue.append((result, chain + [name], depth + 1))

            smart_funcs = list(SMART_DECODERS_CHEAP)
            if depth <= EXPENSIVE_DECODER_MAX_DEPTH:
                smart_funcs += SMART_DECODERS_EXPENSIVE

            for func in smart_funcs:
                try:
                    results = func(current)
                except Exception:
                    results = None
                if not results:
                    continue
                for result, label in results:
                    if result is None or result == current or result in visited:
                        continue
                    visited.add(result)
                    produced_children = True
                    if verbose:
                        print(f"{C.DIM}  [depth {depth}] {' -> '.join(chain + [label])}{C.END}")
                    queue.append((result, chain + [label], depth + 1))

        if not produced_children:
            leaf_candidates.append(SolveResult(current, chain, score_text(current), None, depth))

    flag_hits.sort(key=lambda r: (r.depth, -r.score))
    leaf_candidates.sort(key=lambda r: -r.score)
    return flag_hits, leaf_candidates, nodes_explored


# ============================================================================
#  5. DISPLAY / PRETTY-PRINTING HELPERS
# ============================================================================

def print_banner():
    print(f"{C.CYAN}{C.BOLD}")
    print("=" * 70)
    print("  CTF AUTO-DECODER  --  multi-layer encoding / cipher detective")
    print("=" * 70)
    print(f"{C.END}{C.DIM}Paste an encoded/encrypted string and I'll try to peel back every")
    print(f"layer automatically. Type 'menu' for the manual toolkit, 'help' for")
    print(f"usage notes, or 'quit' to exit.{C.END}")


def best_effort_text(data: bytes) -> str:
    """Human-friendly rendering: real UTF-8 if possible, else latin1 fallback."""
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin1')


def hexdump(data: bytes, max_bytes=256) -> str:
    truncated = len(data) > max_bytes
    view = data[:max_bytes]
    lines = []
    for i in range(0, len(view), 16):
        chunk = view[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f'  {i:06x}  {hex_part}  |{ascii_part}|')
    if truncated:
        lines.append(f'  ... ({len(data) - max_bytes} more bytes)')
    return '\n'.join(lines)


def print_chain(chain):
    if not chain:
        print(f"  {C.DIM}(input was already plaintext -- no decoding needed){C.END}")
        return
    arrow = f" {C.DIM}->{C.END} "
    print(f"  {C.BOLD}Chain:{C.END} " + arrow.join(chain))


def print_flag_result(result: 'SolveResult', rank: int):
    print(f"\n{C.GREEN}{C.BOLD}[{rank}] Flag found:{C.END}")
    print_chain(result.chain)
    text = best_effort_text(result.bytes_val)
    # Highlight the matched flag substring in green/bold within the text.
    if result.flag and result.flag in text:
        highlighted = text.replace(result.flag, f"{C.BOLD}{C.GREEN}{result.flag}{C.END}{C.CYAN}")
        print(f"  {C.BOLD}Result:{C.END} {C.CYAN}{highlighted}{C.END}")
    else:
        print(f"  {C.BOLD}Result:{C.END} {text}")


def print_candidate_result(result: 'SolveResult', rank: int):
    print(f"\n{C.YELLOW}[{rank}]{C.END} (score {result.score:.0f})")
    print_chain(result.chain)
    file_type = identify_file_type(result.bytes_val)
    if file_type:
        print(f"  {C.BOLD}Looks like:{C.END} {file_type} (binary, not text)")
        print(hexdump(result.bytes_val, max_bytes=128))
    else:
        text = best_effort_text(result.bytes_val)
        shown = text if len(text) <= 400 else text[:400] + f"{C.DIM}...(truncated){C.END}"
        print(f"  {C.BOLD}Result:{C.END} {shown}")


def run_auto_solve(user_input: str, max_depth=6, max_nodes=1500, verbose=False, save_binary=True):
    """Drives bfs_solve on a pasted string and prints a full report."""
    if not user_input.strip():
        print(f"{C.YELLOW}(empty input, nothing to decode){C.END}")
        return

    start_bytes = user_input.encode('utf-8', errors='replace')
    hint = detect_hash(user_input)
    if hint:
        print(f"{C.YELLOW}Note:{C.END} this looks like a {hint} hash. Hashes are one-way and "
              f"can't be decoded -- only cracked by guessing (dictionary/brute-force), "
              f"which is outside what this tool does.")
        print(f"{C.DIM}Stopping here rather than trying (and failing) to decode a hash "
              f"as if it were an encoding. Use the manual toolkit for other operations.{C.END}")
        return

    print(f"{C.DIM}Analyzing {len(user_input)} characters...{C.END}")
    t0 = time.time()
    flag_hits, leaf_candidates, nodes_explored = bfs_solve(
        start_bytes, max_depth=max_depth, max_nodes=max_nodes, verbose=verbose)
    elapsed = time.time() - t0

    if flag_hits:
        seen_flags = set()
        rank = 0
        for result in flag_hits:
            if result.flag in seen_flags:
                continue
            seen_flags.add(result.flag)
            rank += 1
            print_flag_result(result, rank)
            if rank >= 5:
                break
    else:
        print(f"\n{C.YELLOW}No confident flag pattern found.{C.END} "
              f"Showing the best-scoring candidate result(s) -- one of these "
              f"may still be your answer, especially if your flag uses an "
              f"unusual wrapper format:")
        shown = 0
        seen_texts = set()
        for result in leaf_candidates:
            if result.score < 90:
                break
            key = result.bytes_val
            if key in seen_texts:
                continue
            seen_texts.add(key)
            shown += 1
            print_candidate_result(result, shown)
            if shown >= 5:
                break
        if shown == 0:
            print(f"{C.RED}Nothing that looks like readable text turned up automatically.{C.END}")
            print(f"This could mean: the encoding needs a key/password this tool doesn't "
                  f"know (try the manual toolkit -- type 'menu'), it's a cipher this tool "
                  f"doesn't cover, or it's genuinely random/binary data.")
            if save_binary and leaf_candidates:
                best_raw = leaf_candidates[0].bytes_val
                offer_save_raw_bytes(best_raw)

    print(f"\n{C.DIM}({nodes_explored} decode paths explored in {elapsed:.1f}s){C.END}")


def offer_save_raw_bytes(data: bytes):
    file_type = identify_file_type(data)
    label = f" ({file_type})" if file_type else ""
    print(f"\n{C.DIM}Best-effort raw bytes{label}:{C.END}")
    print(hexdump(data, max_bytes=128))
    try:
        answer = input(f"{C.CYAN}Save these raw bytes to a file? [y/N]{C.END} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if answer == 'y':
        default_name = 'decoded_output' + (_guess_extension(file_type) if file_type else '.bin')
        try:
            name = input(f"Filename [{default_name}]: ").strip() or default_name
        except (EOFError, KeyboardInterrupt):
            print()
            return
        try:
            with open(name, 'wb') as f:
                f.write(data)
            print(f"{C.GREEN}Saved to {name}{C.END}")
        except OSError as e:
            print(f"{C.RED}Couldn't save file: {e}{C.END}")


def _guess_extension(file_type: str) -> str:
    mapping = {
        'PNG image': '.png', 'JPEG image': '.jpg', 'GIF image': '.gif',
        'ZIP archive': '.zip', 'PDF document': '.pdf', 'ELF executable': '.elf',
        'BMP image': '.bmp', 'GZIP archive': '.gz', 'BZIP2 archive': '.bz2',
        '7-Zip archive': '.7z', 'RAR archive': '.rar', 'MP4 video': '.mp4',
        'MP3 audio': '.mp3',
    }
    return mapping.get(file_type, '.bin')


# ============================================================================
#  6. MANUAL TOOLKIT
#     Explicit, user-directed operations -- for when auto-solve doesn't nail
#     it, or when you already know (or want to guess) a key/shift/parameter.
# ============================================================================

def _read(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        raise


def _show_bytes_result(data: bytes):
    text = best_effort_text(data)
    file_type = identify_file_type(data)
    if file_type:
        print(f"{C.BOLD}Result looks like:{C.END} {file_type} (binary)")
        print(hexdump(data))
        return
    flag = contains_flag(text) or contains_generic_flag_shape(text)
    if flag:
        highlighted = text.replace(flag, f"{C.BOLD}{C.GREEN}{flag}{C.END}")
        print(f"{C.BOLD}Result:{C.END} {highlighted}")
    else:
        print(f"{C.BOLD}Result:{C.END} {text}")


def menu_base64():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_base64_std(text.encode()) or dec_base64_urlsafe(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look like valid Base64.{C.END}")
            return
        _show_bytes_result(result)
    else:
        print(f"{C.BOLD}Result:{C.END} {base64.b64encode(text.encode()).decode()}")


def menu_base32():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_base32(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look like valid Base32.{C.END}")
            return
        _show_bytes_result(result)
    else:
        print(f"{C.BOLD}Result:{C.END} {base64.b32encode(text.encode()).decode()}")


def menu_hex():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_hex(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look like valid hex.{C.END}")
            return
        _show_bytes_result(result)
    else:
        print(f"{C.BOLD}Result:{C.END} {text.encode().hex()}")


def menu_base85():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    variant = _read("  Variant: (b)85 or (a)scii85? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_ascii85(text.encode()) if variant.startswith('a') else dec_base85(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look valid.{C.END}")
            return
        _show_bytes_result(result)
    else:
        if variant.startswith('a'):
            print(f"{C.BOLD}Result:{C.END} {base64.a85encode(text.encode()).decode()}")
        else:
            print(f"{C.BOLD}Result:{C.END} {base64.b85encode(text.encode()).decode()}")


def menu_base58():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_base58(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look like valid Base58.{C.END}")
            return
        _show_bytes_result(result)
    else:
        data = text.encode()
        num = int.from_bytes(data, 'big')
        out = ''
        while num > 0:
            num, r = divmod(num, 58)
            out = _B58_ALPHABET[r] + out
        pad = len(data) - len(data.lstrip(b'\x00'))
        print(f"{C.BOLD}Result:{C.END} {_B58_ALPHABET[0] * pad + out}")


def menu_rot13():
    text = _read("  Input: ")
    print(f"{C.BOLD}Result:{C.END} {codecs.encode(text, 'rot13')}")


def menu_caesar():
    text = _read("  Input: ")
    shift_str = _read("  Shift amount (blank = show all 25): ").strip()
    if shift_str:
        try:
            shift = int(shift_str) % 26
        except ValueError:
            print(f"{C.RED}Not a number.{C.END}")
            return
        print(f"{C.BOLD}Result:{C.END} {caesar_shift_text(text, shift)}")
    else:
        for shift in range(1, 26):
            print(f"  shift {shift:2d}: {caesar_shift_text(text, shift)}")


def menu_atbash():
    text = _read("  Input: ")
    result = dec_atbash(text.encode())
    print(f"{C.BOLD}Result:{C.END} {best_effort_text(result) if result else '(no letters to transform)'}")


def menu_vigenere():
    mode = _read("  (e)ncrypt, (d)ecrypt with a known key, or (c)rack without one? ").strip().lower()
    if mode.startswith('c'):
        text = _read("  Ciphertext: ")
        result = dec_vigenere_crack(text.encode())
        if not result:
            print(f"{C.RED}Couldn't confidently crack this -- it may be too short for "
                  f"frequency analysis (works best with 100+ letters), or it isn't "
                  f"actually a Vigenere cipher.{C.END}")
            return
        for i, (data, label) in enumerate(result, 1):
            print(f"\n{C.BOLD}[{i}] {label}{C.END}")
            _show_bytes_result(data)
        return
    text = _read("  Text: ")
    key = _read("  Key: ").strip()
    if not key or not key.isalpha():
        print(f"{C.RED}Key must be letters only.{C.END}")
        return
    if mode.startswith('e'):
        # Encrypt = decode with the negated shift, reuse vigenere_decode_text
        inv_key = ''.join(chr((26 - (ord(c.lower()) - 97)) % 26 + 97) for c in key)
        print(f"{C.BOLD}Result:{C.END} {vigenere_decode_text(text, inv_key)}")
    else:
        print(f"{C.BOLD}Result:{C.END} {vigenere_decode_text(text, key)}")


def menu_xor():
    mode = _read("  (k)nown key, or (b)rute-force single-byte / (r)epeating-key crack? ").strip().lower()
    if mode.startswith('b'):
        text = _read("  Ciphertext (as raw text, or prefix with 0x for hex): ").strip()
        data = bytes.fromhex(text[2:]) if text.lower().startswith('0x') else text.encode()
        result = dec_xor_single_byte(data)
        if not result:
            print(f"{C.RED}No promising single-byte key found.{C.END}")
            return
        for i, (out, label) in enumerate(result, 1):
            print(f"\n{C.BOLD}[{i}] {label}{C.END}")
            _show_bytes_result(out)
        return
    if mode.startswith('r'):
        text = _read("  Ciphertext (as raw text, or prefix with 0x for hex): ").strip()
        data = bytes.fromhex(text[2:]) if text.lower().startswith('0x') else text.encode()
        result = dec_xor_repeating(data)
        if not result:
            print(f"{C.RED}Couldn't confidently crack this -- it may be too short "
                  f"(works best with 150+ bytes), or the key may be longer than "
                  f"this tool searches for.{C.END}")
            return
        for i, (out, label) in enumerate(result, 1):
            print(f"\n{C.BOLD}[{i}] {label}{C.END}")
            _show_bytes_result(out)
        return
    text = _read("  Text (as raw text, or prefix with 0x for hex): ").strip()
    data = bytes.fromhex(text[2:]) if text.lower().startswith('0x') else text.encode()
    key_str = _read("  Key (as text, or prefix with 0x for hex bytes): ").strip()
    key = bytes.fromhex(key_str[2:]) if key_str.lower().startswith('0x') else key_str.encode()
    if not key:
        print(f"{C.RED}Key can't be empty.{C.END}")
        return
    result = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    _show_bytes_result(result)


def menu_binary():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_binary(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look like valid binary (0s and 1s, multiple of 8 bits).{C.END}")
            return
        _show_bytes_result(result)
    else:
        print(f"{C.BOLD}Result:{C.END} {' '.join(format(b, '08b') for b in text.encode())}")


def menu_octal():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_octal(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look like space-separated octal bytes.{C.END}")
            return
        _show_bytes_result(result)
    else:
        print(f"{C.BOLD}Result:{C.END} {' '.join(format(b, 'o') for b in text.encode())}")


def menu_decimal():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_decimal(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look like space/comma-separated decimal bytes (0-255).{C.END}")
            return
        _show_bytes_result(result)
    else:
        print(f"{C.BOLD}Result:{C.END} {' '.join(str(b) for b in text.encode())}")


def menu_url():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_url(text.encode())
        _show_bytes_result(result if result is not None else text.encode())
    else:
        print(f"{C.BOLD}Result:{C.END} {quote_from_bytes(text.encode())}")


def menu_morse():
    mode = _read("  (e)ncode or (d)ecode? ").strip().lower()
    text = _read("  Input: ")
    if mode.startswith('d'):
        result = dec_morse(text.encode())
        if result is None:
            print(f"{C.RED}That doesn't look like Morse code (dots, dashes, spaces, /).{C.END}")
            return
        _show_bytes_result(result)
    else:
        words = text.upper().split(' ')
        encoded_words = [' '.join(_MORSE.get(c, '') for c in w if c in _MORSE) for w in words]
        print(f"{C.BOLD}Result:{C.END} {' / '.join(encoded_words)}")


def menu_reverse():
    text = _read("  Input: ")
    print(f"{C.BOLD}Result:{C.END} {text[::-1]}")


def menu_compression():
    algo = _read("  Which? (z)lib / (g)zip / (b)z2 / (l)zma / raw-(d)eflate: ").strip().lower()
    mode = _read("  (c)ompress or (d)ecompress? ").strip().lower()
    if mode.startswith('d'):
        text = _read("  Input (as hex, prefix 0x, or paste raw text): ").strip()
        data = bytes.fromhex(text[2:]) if text.lower().startswith('0x') else text.encode('latin1')
        try:
            if algo.startswith('z'):
                result = zlib.decompress(data)
            elif algo.startswith('g'):
                result = gzip.decompress(data)
            elif algo.startswith('b'):
                result = bz2.decompress(data)
            elif algo.startswith('l'):
                result = lzma.decompress(data)
            else:
                result = zlib.decompressobj(wbits=-15).decompress(data)
        except Exception as e:
            print(f"{C.RED}Decompression failed: {e}{C.END}")
            return
        _show_bytes_result(result)
    else:
        text = _read("  Input: ")
        data = text.encode()
        if algo.startswith('z'):
            result = zlib.compress(data)
        elif algo.startswith('g'):
            result = gzip.compress(data)
        elif algo.startswith('b'):
            result = bz2.compress(data)
        elif algo.startswith('l'):
            result = lzma.compress(data)
        else:
            co = zlib.compressobj(wbits=-15)
            result = co.compress(data) + co.flush()
        print(f"{C.BOLD}Result (hex):{C.END} {result.hex()}")


def menu_hash_id():
    text = _read("  Paste the hash: ").strip()
    hint = detect_hash(text)
    if hint:
        print(f"{C.BOLD}Looks like:{C.END} {hint}")
        print(f"{C.DIM}Hashes are one-way -- there's no decoding them, only cracking by "
              f"guessing (dictionary attack, rainbow tables, brute force), which is "
              f"outside what this tool does. Try an online hash-lookup service or "
              f"a dedicated cracking tool (e.g. hashcat, John the Ripper) if you "
              f"believe it's a common/weak password.{C.END}")
    else:
        print(f"{C.YELLOW}Doesn't match a common hash length (MD5/SHA-1/SHA-256/etc).{C.END}")


MENU_ITEMS = [
    ("Base64 encode/decode", menu_base64),
    ("Base32 encode/decode", menu_base32),
    ("Hex (Base16) encode/decode", menu_hex),
    ("Base85 / Ascii85 encode/decode", menu_base85),
    ("Base58 encode/decode", menu_base58),
    ("ROT13", menu_rot13),
    ("Caesar cipher (choose shift, or show all)", menu_caesar),
    ("Atbash cipher", menu_atbash),
    ("Vigenere cipher (encrypt/decrypt/crack)", menu_vigenere),
    ("XOR (known key / brute-force / crack repeating-key)", menu_xor),
    ("Binary encode/decode", menu_binary),
    ("Octal encode/decode", menu_octal),
    ("Decimal byte-list encode/decode", menu_decimal),
    ("URL encode/decode", menu_url),
    ("Morse code encode/decode", menu_morse),
    ("Reverse a string", menu_reverse),
    ("Compression (zlib/gzip/bz2/lzma/raw-deflate)", menu_compression),
    ("Identify a hash (MD5/SHA-1/SHA-256/...)", menu_hash_id),
]


def manual_menu():
    while True:
        print(f"\n{C.CYAN}{C.BOLD}--- Manual Toolkit ---{C.END}")
        for i, (label, _) in enumerate(MENU_ITEMS, 1):
            print(f"  {i:2d}. {label}")
        print(f"   0. Back to auto-solve")
        try:
            choice = _read(f"{C.CYAN}>{C.END} ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice in ('0', '', 'q', 'quit', 'back'):
            return
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(MENU_ITEMS)):
                raise ValueError
        except ValueError:
            print(f"{C.RED}Not a valid option.{C.END}")
            continue
        label, func = MENU_ITEMS[idx]
        print(f"\n{C.BOLD}{label}{C.END}")
        try:
            func()
        except (EOFError, KeyboardInterrupt):
            return
        except Exception as e:
            print(f"{C.RED}Error: {e}{C.END}")


# ============================================================================
#  7. MAIN / CLI
# ============================================================================

HELP_TEXT = """
This tool tries to automatically detect and reverse chains of encoding and
simple ciphers -- e.g. Base32 -> Base64 -> single-byte XOR -> plaintext.

Auto-solve covers: Base16/32/58/64/85, binary, octal, decimal byte-lists,
URL-encoding, Morse code, ROT13/Caesar (brute-forced), Atbash, single-byte
XOR (brute-forced), repeating-key XOR (auto key-recovery), Vigenere (auto
key-recovery), gzip/zlib/bz2/lzma/raw-deflate decompression, and reversed
strings -- chained to arbitrary depth.

Repeating-key XOR and Vigenere cracking use frequency analysis, which needs
enough ciphertext to work reliably (very roughly: 100+ characters). Shorter
ciphertext may not auto-crack -- if you know or can guess the key, use the
manual toolkit ('menu') instead, which is exact regardless of length.

Commands at the input prompt:
  menu       switch to the manual toolkit (explicit operations, known keys)
  help       show this message
  quit       exit
Anything else is treated as text to auto-decode.
"""


def interactive_main(args):
    _disable_colour_if_needed()
    print_banner()
    while True:
        print()
        try:
            user_input = input(f"{C.CYAN}>{C.END} ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            return
        stripped = user_input.strip()
        low = stripped.lower()
        if low in ('quit', 'exit', 'q'):
            print("Goodbye!")
            return
        if low in ('menu', 'manual', 'm'):
            manual_menu()
            continue
        if low in ('help', 'h', '?'):
            print(HELP_TEXT)
            continue
        if not stripped:
            continue
        run_auto_solve(stripped, max_depth=args.max_depth, max_nodes=args.max_nodes,
                        verbose=args.verbose)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog='ctf_decoder.py',
        description='Auto-detect and decode chained encodings/ciphers for CTF challenges.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_TEXT)
    parser.add_argument('text', nargs='?', default=None,
                         help='the encoded/encrypted string to decode (omit for interactive mode)')
    parser.add_argument('-f', '--file', metavar='PATH',
                         help='read the encoded/encrypted text from a file instead')
    parser.add_argument('--manual', action='store_true',
                         help='jump straight into the manual toolkit')
    parser.add_argument('-v', '--verbose', action='store_true',
                         help='show every decode path explored, not just the final result')
    parser.add_argument('--max-depth', type=int, default=6,
                         help='max chained decoding layers to try (default: 6)')
    parser.add_argument('--max-nodes', type=int, default=1500,
                         help='max decode attempts before giving up (default: 1500)')
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    _disable_colour_if_needed()

    if args.manual:
        print_banner()
        manual_menu()
        return

    if args.file:
        try:
            with open(args.file, 'r', errors='replace') as f:
                content = f.read()
        except OSError as e:
            print(f"{C.RED}Couldn't read {args.file}: {e}{C.END}", file=sys.stderr)
            sys.exit(1)
        run_auto_solve(content.strip(), max_depth=args.max_depth,
                        max_nodes=args.max_nodes, verbose=args.verbose)
        return

    if args.text is not None:
        run_auto_solve(args.text, max_depth=args.max_depth,
                        max_nodes=args.max_nodes, verbose=args.verbose)
        return

    interactive_main(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)
