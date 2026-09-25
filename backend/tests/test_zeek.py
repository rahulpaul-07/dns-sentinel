"""Zeek dns.log parser: header-driven column mapping."""
import os

from zeek import iter_zeek_dns

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "samples", "dns.log")


def test_parses_bundled_sample():
    with open(SAMPLE, encoding="utf-8") as fh:
        rows = list(iter_zeek_dns(fh))
    assert rows and rows[0] == {
        "query": "www.google.com", "source_ip": "192.168.1.100", "qtype": "A", "ts": 1696951800.123456,
    }


def test_reordered_columns_still_map_correctly():
    log = ("#separator \\x09\n"
           "#fields\tquery\tid.orig_h\tts\n"
           "evil.example\t10.0.0.9\t1.5\n")
    assert list(iter_zeek_dns(log)) == [
        {"query": "evil.example", "source_ip": "10.0.0.9", "qtype": "A", "ts": 1.5}
    ]


def test_skips_empty_queries_short_rows_and_non_dns_logs():
    log = ("#separator \\x09\n"
           "#fields\tts\tid.orig_h\tquery\n"
           "1\t10.0.0.1\t-\n"
           "2\t10.0.0.1\n"
           "#fields\tts\tuid\tmethod\n"
           "3\tC1\tGET\n")
    assert list(iter_zeek_dns(log)) == []
