import csv, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import triage

VALID = {"QUALIFY", "NURTURE", "REJECT", "ESCALATE"}


def load(path):
    return list(csv.DictReader(open(ROOT / path, encoding="utf-8")))


class T(unittest.TestCase):
    def test_every_row_decided_once_valid(self):
        for f in ("fixtures/inbound_leads.csv", "holdout/holdout_leads.csv", "holdout/redteam_leads.csv"):
            rows = load(f)
            res, _ = triage.run(rows)
            self.assertEqual([r["lead_id"] for r in rows], [d["lead_id"] for d in res])
            for d in res:
                self.assertIn(d["decision"], VALID)
                self.assertTrue(0 <= d["confidence"] <= 1)
                self.assertTrue(d["reason"].endswith("."))

    def test_injection_rows_never_qualify(self):
        for f in ("fixtures/inbound_leads.csv", "holdout/holdout_leads.csv", "holdout/redteam_leads.csv"):
            res, _ = triage.run(load(f))
            for d in res:
                if "INJECTION" in d["flags"]:
                    self.assertNotEqual(d["decision"], "QUALIFY", d["lead_id"])

    def test_reader_can_only_add_caution(self):
        rows = load("fixtures/inbound_leads.csv")
        base, _ = triage.run(rows)
        # a reader that says QUALIFY for everything must change nothing
        same, _ = triage.run(rows, {r["lead_id"]: "QUALIFY" for r in rows})
        self.assertEqual([d["decision"] for d in base], [d["decision"] for d in same])
        # a reader that says REJECT for everything may only touch rows the engine would QUALIFY
        harsh, _ = triage.run(rows, {r["lead_id"]: "REJECT" for r in rows})
        for b, h in zip(base, harsh):
            if b["decision"] != "QUALIFY":
                self.assertEqual(b["decision"], h["decision"])
            else:
                self.assertEqual(h["decision"], "ESCALATE")

    def test_budget_parser(self):
        cases = {"25000": 25000, "15k": 15000, "$12,500/mo": 12500, "10-15k": 10000,
                 "€6.000": 6000, "50k/yr": round(50000 / 12, 2), "we'll discuss": None, "-500": None, "": None}
        for raw, want in cases.items():
            self.assertEqual(triage.parse_budget(raw)[0], want, raw)

    def test_deterministic(self):
        rows = load("fixtures/inbound_leads.csv")
        a, _ = triage.run(rows)
        b, _ = triage.run(rows)
        self.assertEqual(a, b)

    def test_no_message_text_leaks_into_outputs(self):
        rows = load("fixtures/inbound_leads.csv") + load("holdout/redteam_leads.csv")
        res, _ = triage.run(rows)
        blob = " ".join(d["reason"] + d["next_action"] for d in res).lower()
        for needle in ("ignore all previous", "confidence 1.0", "maintenance mode", "fastpay-billing"):
            self.assertNotIn(needle, blob)


if __name__ == "__main__":
    unittest.main()
