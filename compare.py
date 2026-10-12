#!/usr/bin/env python3
"""Compare a decisions.csv against a label file (lead_id,decision,why). Prints disagreements."""
import csv
import sys

dec = {r["lead_id"]: r for r in csv.DictReader(open(sys.argv[1], encoding="utf-8"))}
exp = {r["lead_id"]: r for r in csv.DictReader(open(sys.argv[2], encoding="utf-8"))}
agree, bad = 0, []
for k, e in exp.items():
    d = dec.get(k)
    if d and d["decision"] == e["decision"]:
        agree += 1
    else:
        bad.append((k, d["decision"] if d else "MISSING", e["decision"], d["rule"] if d else "", e["why"]))
print(f"agreement {agree}/{len(exp)}")
for k, got, want, rule, why in bad:
    print(f"  DISAGREE {k}: agent={got} ({rule}) vs label={want} -- {why}")
