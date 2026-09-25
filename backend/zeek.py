"""Parser for Zeek dns.log (TSV) files.

Column positions are read from the `#fields` header instead of being assumed,
so logs from Zeek deployments with extra or reordered fields parse correctly.
"""
from typing import Iterable, Iterator

_EMPTY = {"-", "(empty)", ""}


def iter_zeek_dns(content: "str | Iterable[str]") -> Iterator[dict]:
    """Yield {"query", "source_ip", "qtype", "ts"} dicts from a Zeek dns.log.

    `content` may be the whole file as a string or any iterable of lines.
    Rows before a `#fields` header, rows with too few columns and rows with an
    empty query are skipped.
    """
    lines = content.splitlines() if isinstance(content, str) else content
    sep = "\t"
    idx = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if line.startswith("#separator"):
            token = line.split(" ", 1)[1].strip() if " " in line else "\\x09"
            sep = token.encode().decode("unicode_escape") if token.startswith("\\x") else token
            continue
        if line.startswith("#fields"):
            names = line.split(sep)[1:]
            try:
                idx = {k: names.index(k) for k in ("ts", "id.orig_h", "query")}
            except ValueError:
                idx = None  # not a dns.log
                continue
            idx["qtype"] = names.index("qtype_name") if "qtype_name" in names else None
            continue
        if not line or line.startswith("#") or idx is None:
            continue
        parts = line.split(sep)
        needed = max(v for v in idx.values() if v is not None)
        if len(parts) <= needed:
            continue
        query = parts[idx["query"]]
        if query in _EMPTY:
            continue
        qtype = parts[idx["qtype"]] if idx["qtype"] is not None else "A"
        try:
            ts = float(parts[idx["ts"]])
        except ValueError:
            ts = None
        yield {
            "query": query,
            "source_ip": parts[idx["id.orig_h"]],
            "qtype": "A" if qtype in _EMPTY else qtype,
            "ts": ts,
        }
