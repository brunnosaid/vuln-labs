# modules/utils.py
import math
import re
import hashlib
import string

PRINTABLE_RE = re.compile(rb'[' + re.escape(bytes(string.printable, 'ascii')) + rb']{4,}')

def sha256_of_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def extract_printable_strings(b: bytes, min_len=4):
    return [s.decode('utf-8', errors='ignore') for s in PRINTABLE_RE.findall(b)]

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    probs = [float(data.count(bytes([i]))) / len(data) for i in range(256)]
    e = 0.0
    for p in probs:
        if p > 0:
            e -= p * math.log2(p)
    return e

SHELL_INDICATORS = [
    r'\b/bin/bash\b', r'\bnc\b', r'\bncat\b', r'\bnetcat\b', r'\bwget\b', r'\bcurl\b',
    r'\bwhoami\b', r'\bsh -i\b', r'\bpython -c\b', r'\bpython3 -c\b', r'\bpowershell\b'
]
SHELL_RE = re.compile('|'.join(SHELL_INDICATORS), re.IGNORECASE)

def suspicious_shell_text(text: str):
    matches = SHELL_RE.findall(text)
    extra = bool(re.search(r'(\|\s*sh|>\s*/dev/null|>/dev/tcp|/dev/tcp)', text))
    return {'matches': matches, 'extra': extra}
