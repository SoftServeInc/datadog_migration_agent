#!/usr/bin/env python3
"""Collapse OpenTelemetry Collector export-failure logs into one row per exporter.

Reads collector logs on stdin. The raw lines are large JSON blobs repeated once
per failed batch, which is unreadable in a terminal; this reports how many
failures each exporter had, how much telemetry was lost, and the reason.
"""
import collections
import re
import sys

COMP = re.compile(r'"otelcol\.component\.id": "([^"]+)"')
SIG = re.compile(r'"otelcol\.signal": "([^"]+)"')
DROP = re.compile(r'"dropped_items": (\d+)')
WHY = re.compile(r'"error": "(.*?)", "dropped_items', re.S)
NOISE = re.compile(r"^(not retryable error: )?Permanent error: ")

rows = collections.defaultdict(lambda: {"n": 0, "dropped": 0, "why": ""})

for line in sys.stdin:
    if "Exporting failed" not in line:
        continue
    comp = COMP.search(line)
    if not comp:
        continue
    sig = SIG.search(line)
    drop = DROP.search(line)
    why = WHY.search(line)
    row = rows[(comp.group(1), sig.group(1) if sig else "?")]
    row["n"] += 1
    row["dropped"] += int(drop.group(1)) if drop else 0
    if why:
        row["why"] = NOISE.sub("", why.group(1).replace('\\"', '"'))[:120]

if not rows:
    print("  no export failures in the recent log window")
    sys.exit(0)

for (comp, sig), row in sorted(rows.items(), key=lambda kv: -kv[1]["dropped"]):
    print("  {}  [{}]".format(comp, sig))
    print("    {} failures, {} items dropped".format(row["n"], row["dropped"]))
    if row["why"]:
        print("    {}".format(row["why"]))
