"""Atom extraction and matching.

An *atom* is a concrete value that can be followed from a tool output into a
tool-call argument: an email address, a URL, a number of four or more digits,
or a whole short argument string. Matching is exact-substring (deterministic),
with a word-boundary rule for short atoms so that, e.g., the file id '13' is
not matched inside '2013'.
"""
from __future__ import annotations

import re

# email | url | www... | run of 4+ digits
ATOM = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+|www\.\S+|\b\d{4,}\b")


def values(x):
    """Yield every scalar inside a nested dict/list argument value, as str."""
    if isinstance(x, dict):
        for v in x.values():
            yield from values(v)
    elif isinstance(x, list):
        for v in x:
            yield from values(v)
    elif x is not None:
        yield str(x)


def atoms(v: str) -> set[str]:
    """Atoms inside a single value string, plus the whole string if 1-200 chars."""
    out = set(ATOM.findall(v))
    if 1 <= len(v) <= 200:
        out.add(v)
    return out


def occurs(atom: str, text: str) -> bool:
    """True if `atom` occurs in `text`.

    Atoms shorter than four characters match only as whole tokens (not inside a
    longer run of identifier characters), so short ids like '13' are precise.
    """
    if len(atom) < 4:
        return re.search(rf"(?<![\w.\-:/]){re.escape(atom)}(?![\w.\-:/])", text) is not None
    return atom in text
