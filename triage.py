#!/usr/bin/env python3
"""Lead triage agent - first pass over an inbound-leads CSV.

Design (see README.md):
  ingest -> sanitize -> extract features/flags -> cross-row dedupe -> policy table -> decisions + trace

Trust boundary: the free-text `message` field is DATA. It is read only by the
extractors in `scan_message()` (regex flags). Nothing in the message can change
a threshold, a rule, or an output field. If a message looks like an instruction
to the agent, it is quarantined: the decision is then computed from structured
fields only, and such a row can never end up as QUALIFY.

Pure stdlib. No network. No LLM call in this file (an independent LLM reader
pass is run separately and merged by `--reader`, which can only make the
outcome MORE cautious).

Usage:
  python3 triage.py fixtures/inbound_leads.csv --out out/ [--reader logs/reader_pass.json]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import re
from difflib import SequenceMatcher
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

VERSION = "v2"

# ---- policy knobs (assumptions, not facts; see README "Assumed" labels) -------
QUALIFY_MIN_BUDGET = 5000          # USD / month  [Assumed]
IMPLAUSIBLE_BUDGET = 500_000       # USD / month  [Assumed]
MIN_NEED_WORDS = 8                 # words of real message needed to call a need "stated"

DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
              "yopmail.com", "trashmail.com", "sharklasers.com"}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
            "proton.me", "protonmail.com", "aol.com", "gmx.com"}
EXEC_EXT = (".exe", ".scr", ".bat", ".msi", ".vbs", ".jar", ".apk", ".cmd", ".ps1", ".com")

RX = {
    "INJECTION": [
        r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\b[^.\n]{0,30}\binstructions?",
        r"\b(?:classify|mark|label|rate|score|output|set)\b[^.\n]{0,40}\b(?:qualify|qualified|decision|confidence)\b",
        r"\byou\s+are\s+now\b",
        r"\b(?:system|developer|admin)\s*(?:prompt|mode|override)\b",
        r"^\s*system\s*:",
        r"\bskip\s+(?:all\s+)?(?:checks|validation|review)\b",
        r"\bdisregard\b[^.\n]{0,30}\b(?:rules|instructions|policy)\b",
        # v2: language-agnostic / role-play / exfiltration phrasing (found by the red-team set)
        r"\bmaintenance\s+mode\b", r"\brouting\s+admin\b", r"\bmark\s+every\s+lead\b",
        r"\b(?:this|the)\s+(?:system|bot|agent|model|assistant|ai)\b[^.\n]{0,40}\b(?:reads?|screens?|processes|triages?)\b",
        r"system,?\s+das\s+diese\s+nachricht\s+liest",
        r"\b(?:paste|reveal|print|output|show)\b[^.\n]{0,40}\b(?:configuration|config|system\s+prompt|instructions|email\s+addresses\s+of\s+all)\b",
    ],
    "PRIVACY": [
        r"\b(?:gdpr|ccpa|cpra)\b", r"article\s*17", r"right\s+to\s+(?:be\s+forgotten|erasure)",
        r"delete\s+(?:all\s+)?(?:of\s+)?(?:my\s+)?(?:personal\s+)?(?:data|information)",
        r"delete\s+all\s+personal\s+data", r"do\s+not\s+sell",
    ],
    "PHISH_TEXT": [
        r"(?:verify|confirm)\b[^.\n]{0,30}\bpassword", r"account\s+(?:is\s+)?suspended",
        r"overdue\s+invoice", r"avoid\s+service\s+interruption", r"download\s+the\s+attached",
        r"verification\s+code", r"reply\s+with\s+the\s+\d*-?digit\s+code", r"permanent\s+suspension",
        r"will\s+be\s+(?:revoked|suspended|terminated)\b[^.\n]{0,40}(?:hours|days)",
    ],
    "LEGAL": [
        r"letter\s+before\s+action", r"preserve\s+all\s+(?:communications|records)", r"formal\s+letter",
        r"cease\s+and\s+desist", r"(?:filing|file)\s+a\s+complaint", r"\bregulator\b", r"\blawsuit\b",
        r"\bwe\s+act\s+for\b", r"\bsubpoena\b", r"legal\s+counsel",
    ],
    "PRESS": [r"\b(?:reporter|journalist)\b", r"\bon\s+the\s+record\b", r"press\s+inquiry"],
    "ACCESSIBILITY": [r"screen\s+reader", r"accessibility\s+(?:complaint|barrier)", r"\bwcag\b"],
    "MINORS_A": [r"\b(?:kids?|child(?:ren)?|minors?)\b"],
    "MINORS_B": [r"birth\s*dates?", r"child\s+names", r"user\s+table", r"upload\s+the\s+full\s+csv", r"email\s+the\s+kids"],
    "NON_BUYER": [
        r"\bmentor(?:ship)?\b", r"breaking\s+into\s+the\s+industry", r"career\s+advice",
        r"\bare\s+you\s+hiring\b", r"\bmy\s+resume\b", r"\binternships?\b",
    ],
    "VENDOR_PITCH": [
        r"\bpartner\s+with\s+us\b", r"link[\s-]building\s+packages?",
        r"\bwe\s+(?:provide|offer)\s+(?:seo|white|link|backlink)",
    ],
    "AGENCY_RESEARCH": [
        r"for\s+a\s+client\s+of\s+ours", r"comparison\s+for\s+(?:a|our)\s+client",
        r"\bbenchmarking\b", r"similar\s+agency", r"your\s+(?:margins?|tooling\s+stack|retainer\s+tiers)",
    ],
    "ASSET_REQUEST": [
        r"send\s+(?:over\s+)?(?:me\s+|us\s+)?(?:your\s+)?(?:complete\s+|full\s+)?"
        r"(?:methodology|deck|case\s+stud|past\s+client|client\s+results)",
    ],
    "BIG_CLAIM": [r"fortune\s*\d+", r"\bvp\b", r"\bchief\b", r"\bc[eo]o\b"],
    "URGENCY": [r"this\s+week", r"\basap\b", r"ready\s+to\s+sign", r"\btoday\b"],
    "REGULATED": [r"\bhealth(?:care)?\b", r"\bcompliance\b", r"\bbank(?:ing)?\b", r"\blegal\b"],
}
RX = {k: [re.compile(p, re.I | re.M) for p in v] for k, v in RX.items()}
# decision labels in ALL CAPS inside a lead's message are a manipulation tell (case-sensitive on purpose)
LABEL_TOKENS = re.compile(r"\b(?:QUALIFY|NURTURE|ESCALATE|REJECT)\b")

STOP = {
    "es": {"somos", "una", "para", "buscamos", "presupuesto", "tenemos", "este", "con"},
    "fr": {"nous", "sommes", "une", "pour", "cherchons", "budget", "valide", "ce"},
    "de": {"wir", "und", "eine", "für", "suchen", "unser"},
}


# ---------------------------------------------------------------- helpers ------
def any_rx(key: str, text: str) -> bool:
    return any(p.search(text) for p in RX[key])


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def clean_text(raw: str) -> tuple[str, bool]:
    """Strip tags/entities/emoji. Returns (clean, noisy)."""
    t = re.sub(r"<[^>]+>", " ", raw or "")
    t = html.unescape(t)
    t = re.sub(r"[\U00010000-\U0010ffff☀-➿]", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t, t != (raw or "").strip()


def parse_budget(raw: str):
    """-> (value|None, [notes]). Never guesses: unparseable stays None.
    Handles $, EUR/GBP symbols, 15k, ranges (lower bound), /mo, per-year (annualised /12),
    and dot-thousands (7.500 -> 7500, flagged as locale-ambiguous)."""
    s = (raw or "").strip().lower()
    notes: list[str] = []
    if not s:
        return None, ["BUDGET_MISSING"]
    if re.fullmatch(r"-\s*[$€£]?\s*\d+(?:[.,]\d+)?", s):
        return None, ["BUDGET_NEGATIVE"]
    if re.search(r"[€£]|\b(?:eur|gbp)\b", s):
        notes.append("CURRENCY_NON_USD")
        s = re.sub(r"[€£]|\b(?:eur|gbp)\b", "", s)
    s = re.sub(r"\busd\b|\$", "", s)
    annual = bool(re.search(r"/\s*(?:yr|year)|per\s+year|annual(?:ly)?|a\s+year", s))
    s = re.sub(r"/\s*(?:yr|year|mo(?:nth)?)|per\s+(?:year|month)|annual(?:ly)?|a\s+(?:year|month)", "", s).strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{3})+", s):
        s = s.replace(".", "")
        notes.append("BUDGET_LOCALE_THOUSANDS")
    s = s.replace(",", "").strip()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)\s*([km])?", s)
    if m:
        mult = {"k": 1e3, "m": 1e6, None: 1}[m.group(3)]
        val = float(m.group(1)) * mult
        notes.append("BUDGET_RANGE_LOWER_BOUND")
    else:
        m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([km])?", s)
        if not m:
            return None, notes + ["BUDGET_NOT_NUMERIC"]
        mult = {"k": 1e3, "m": 1e6, None: 1}[m.group(2)]
        val = float(m.group(1)) * mult
        if m.group(2) or "$" in (raw or ""):
            notes.append("BUDGET_NORMALIZED")
    if annual:
        val = round(val / 12, 2)
        notes.append("BUDGET_ANNUALIZED")
    return val, notes


def parse_ts(raw: str) -> bool:
    try:
        datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except Exception:
        return False


def norm_company(c: str) -> str:
    c = re.sub(r"[^a-z0-9 ]", "", (c or "").lower())
    c = re.sub(r"\b(inc|llc|ltd|corp|co|group)\b", "", c)
    return re.sub(r"\s+", "", c)


def host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().removeprefix("www.")
    except Exception:
        return ""


def lang_of(text: str) -> str:
    words = set(re.findall(r"[a-zà-ÿ]+", text.lower()))
    best, n = "en", 2
    for code, sw in STOP.items():
        hit = len(words & sw)
        if hit >= n:
            best, n = code, hit
    return best


# ------------------------------------------------------------ the one place -----
def scan_message(msg_clean: str) -> dict:
    """The ONLY function that reads the free-text message. Returns flags, never obeys it."""
    flags = set()
    for key in ("INJECTION", "PRIVACY", "NON_BUYER", "VENDOR_PITCH",
                "AGENCY_RESEARCH", "ASSET_REQUEST", "REGULATED", "LEGAL", "PRESS", "ACCESSIBILITY"):
        if any_rx(key, msg_clean):
            flags.add(key)
    if LABEL_TOKENS.search(msg_clean):
        flags.add("INJECTION")
    phish_hits = sum(1 for p in RX["PHISH_TEXT"] if p.search(msg_clean))
    if phish_hits >= 1:
        flags.add("PHISH_TEXT")
    if phish_hits >= 2:
        flags.add("PHISH_STRONG")
    if any_rx("MINORS_A", msg_clean) and any_rx("MINORS_B", msg_clean):
        flags.add("MINORS_DATA")
    urls = re.findall(r"https?://[^\s)>\"]+", msg_clean, re.I)
    if any(u.lower().split("?")[0].endswith(EXEC_EXT) for u in urls):
        flags.add("EXEC_LINK")
    claim = any_rx("BIG_CLAIM", msg_clean)
    urgent = any_rx("URGENCY", msg_clean)
    emp = None
    m = re.search(r"([\d,]{4,})[\s-]+employee", msg_clean, re.I)
    if m:
        emp = int(m.group(1).replace(",", ""))
    return {"flags": flags, "claim": claim, "urgent": urgent, "employees": emp,
            "words": len(msg_clean.split()), "lang": lang_of(msg_clean)}


def junk_signals(row: dict, msg_clean: str) -> int:
    n = 0
    if (row["name"] or "").strip().lower() in {"test", "asdf", "xxx", "qwerty", "n/a"}:
        n += 1
    local = (row["email"] or "").split("@")[0].lower()
    dom = (row["email"] or "").split("@")[-1].lower()
    if local in {"test", "asdf", "xxx", "qwerty"} or dom.split(".")[0] in {"asdf", "test"}:
        n += 1
    comp = (row["company"] or "").strip().lower()
    if comp in {"asdf", "test", "xxx", "qwerty"}:
        n += 1
    one = msg_clean.replace(" ", "")
    if one and " " not in msg_clean and len(one) >= 6 and re.fullmatch(r"(.{2,6})\1+", one.lower()):
        n += 1
    return n


# ------------------------------------------------------------------ pipeline ----
def featurize(row: dict) -> dict:
    msg_clean, noisy = clean_text(row["message"])
    sc = scan_message(msg_clean)
    flags = set(sc["flags"])
    if noisy:
        flags.add("HTML_NOISE")
    if not parse_ts(row["submitted_at"]):
        flags.add("TIMESTAMP_INVALID")
    budget, bnotes = parse_budget(row["monthly_budget_usd"])
    flags.update(bnotes)
    email = (row["email"] or "").strip().lower()
    edom = email.split("@")[-1] if "@" in email else ""
    if not email:
        flags.add("MISSING_EMAIL")
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", email):
        flags.add("INVALID_EMAIL")
    if edom in DISPOSABLE:
        flags.add("DISPOSABLE_EMAIL")
    freemail = edom in FREEMAIL
    if freemail:
        flags.add("FREEMAIL")
    whost = host(row["website"])
    if whost and edom and not freemail and whost != edom:
        flags.add("DOMAIN_MISMATCH")
    if budget is not None and budget >= IMPLAUSIBLE_BUDGET:
        flags.add("BUDGET_IMPLAUSIBLE")
    if sc["employees"] and budget is not None and sc["employees"] >= 1000 and budget < 1000:
        flags.add("SIZE_BUDGET_MISMATCH")
    if sc["claim"] and sc["urgent"] and freemail and not row["company"].strip() and not whost:
        flags.add("UNVERIFIABLE_IDENTITY")
    if junk_signals(row, msg_clean) >= 2:
        flags.add("JUNK")
    if sc["lang"] != "en":
        flags.add("LANG_" + sc["lang"].upper())
    return {"email": email, "budget": budget, "whost": whost, "flags": flags,
            "has_company": bool(row["company"].strip()), "words": sc["words"],
            "msg_clean": msg_clean}


def dedupe(rows, feats):
    """First occurrence wins. Same email + >=2 of (site, company, budget) -> duplicate;
    same email otherwise -> repeat contact with a different profile."""
    seen: dict[str, list[int]] = {}
    for i, (r, f) in enumerate(zip(rows, feats)):
        e = f["email"]
        for j in range(i):
            pr, pf = rows[j], feats[j]
            if e and pf["email"] == e:
                continue  # exact-email case handled below
            if (f["whost"] and f["whost"] == pf["whost"] and f["budget"] is not None
                    and f["budget"] == pf["budget"]
                    and SequenceMatcher(None, r["name"].lower(), pr["name"].lower()).ratio() >= 0.85):
                f["flags"].add("DUPLICATE")
                f["flags"].add("FUZZY_DUPLICATE")
                f["dup_of"] = pr["lead_id"]
                break
        if not e or "DUPLICATE" in f["flags"]:
            continue
        for j in seen.get(e, []):
            pr, pf = rows[j], feats[j]
            same = sum([
                bool(f["whost"]) and f["whost"] == pf["whost"],
                bool(norm_company(r["company"])) and norm_company(r["company"]) == norm_company(pr["company"]),
                f["budget"] is not None and f["budget"] == pf["budget"],
            ])
            if same >= 2:
                f["flags"].add("DUPLICATE")
                f["dup_of"] = pr["lead_id"]
            else:
                f["flags"].add("REPEAT_CONTACT_CONFLICT")
                f["dup_of"] = pr["lead_id"]
            break
        seen.setdefault(e, []).append(i)


def decide(row: dict, f: dict) -> dict:
    fl, b = f["flags"], f["budget"]
    ref = f.get("dup_of", "")

    def out(dec, rule, reason, conf, route="", nxt=""):
        pen = 0.1 * ("TIMESTAMP_INVALID" in fl) + 0.05 * ("BUDGET_NORMALIZED" in fl) \
            + 0.05 * ("BUDGET_RANGE_LOWER_BOUND" in fl) + 0.1 * ("DOMAIN_MISMATCH" in fl) \
            + 0.05 * ("REGULATED" in fl) + 0.05 * ("CURRENCY_NON_USD" in fl) \
            + 0.05 * ("BUDGET_ANNUALIZED" in fl) + 0.1 * ("BUDGET_LOCALE_THOUSANDS" in fl)
        return {"decision": dec, "rule": rule, "reason": reason,
                "confidence": round(max(0.05, min(0.99, conf - pen)), 2),
                "route_to": route, "next_action": nxt}

    if "EXEC_LINK" in fl or "PHISH_STRONG" in fl:
        return out("REJECT", "R1-security", "Message pushes an urgent payment/credential action with an executable or login link, so it is a phishing/malware attempt, not a lead.",
                   0.95, "security", "Do not click or reply; report to security and block the sender.")
    if "PRIVACY" in fl:
        return out("ESCALATE", "R2-privacy", "Data-erasure request under privacy law with a legal response deadline; not a sales lead and not for automated reply.",
                   0.95, "privacy-legal", "Verify requester identity and handle the erasure request within the statutory window.")
    if fl & {"LEGAL", "PRESS", "ACCESSIBILITY", "MINORS_DATA"}:
        kind = ("minors" if "MINORS_DATA" in fl else "accessibility" if "ACCESSIBILITY" in fl
                else "legal" if "LEGAL" in fl else "press")
        why = {"legal": "Legal-hold / letter-before-action style message from counsel or about a dispute; not a sales lead and needs a human with counsel.",
               "minors": "Request involves personal data of children and direct marketing to minors; compliance risk needs a human decision before any reply.",
               "accessibility": "Accessibility complaint with a stated regulatory escalation; needs a named human response, not an automated one.",
               "press": "Press inquiry with a deadline; not a buyer but must be routed to whoever handles comms, not silently dropped."}[kind]
        return out("ESCALATE", f"R2b-{kind}", why, 0.9,
                   {"legal": "legal", "minors": "privacy-legal", "accessibility": "web-owner", "press": "comms"}[kind],
                   "Route to the owner; do not send an automated sales reply.")
    if "INJECTION" in fl:
        fit = (b is not None and b >= QUALIFY_MIN_BUDGET and f["has_company"] and f["email"]
               and "DISPOSABLE_EMAIL" not in fl)
        if fit:
            return out("ESCALATE", "R3-injection-fit", "Message tries to dictate the agent's decision although the structured fields look plausible, so a human must judge the lead.",
                       0.8, "sales-lead", "Review manually; log the manipulation attempt.")
        return out("REJECT", "R3-injection", "Message contains embedded instructions aimed at the triage agent (quarantined and ignored) and the structured fields (budget, need) do not support a qualified lead.",
                   0.9, "", "Flag the sender as a manipulation attempt; no automated reply.")
    if "JUNK" in fl:
        return out("REJECT", "R4-junk", "Multiple test/keyboard-mash signals and an implausible budget indicate a junk submission.",
                   0.95)
    if "DUPLICATE" in fl:
        return out("REJECT", "R5-duplicate", f"Same contact, site and budget as {ref}; merge any new context into that record instead of working it twice.",
                   0.9, "sales-ops", f"Merge into {ref}.")
    if "NON_BUYER" in fl:
        return out("REJECT", "R6-non-buyer", "Sender is asking for mentoring/career help or a job, not buying services.",
                   0.85, "", "Optional polite template reply.")
    if "VENDOR_PITCH" in fl and (b is None or b == 0):
        return out("REJECT", "R6-vendor", "Sender is selling services to us, not buying.",
                   0.85)
    if "MISSING_EMAIL" in fl or "INVALID_EMAIL" in fl:
        return out("ESCALATE", "R7-no-contact", "Lead looks real but has no usable email, so a human must recover the contact from the source system.",
                   0.7, "sdr", "Look up the contact in the source (e.g., event registrant list).")
    if "DISPOSABLE_EMAIL" in fl and ("ASSET_REQUEST" in fl or not f["whost"]):
        return out("ESCALATE", "R8-disposable", "Disposable email plus a request for proprietary material up front; a human should verify before anything is sent.",
                   0.7, "sales-lead", "Verify identity; send no decks or client results automatically.")
    if "AGENCY_RESEARCH" in fl:
        return out("ESCALATE", "R9-agency-research", "Another agency asking how we structure retainers for a client: partner or competitive intel is a policy call.",
                   0.6, "partnerships", "Decide whether to engage as a partner; share nothing proprietary by default.")
    if "UNVERIFIABLE_IDENTITY" in fl:
        return out("ESCALATE", "R10-unverifiable", "Large claims with urgency from a free-mail address with no company or site; identity must be verified before any pricing talk.",
                   0.65, "sales-lead", "Ask for company and verify on LinkedIn before replying with pricing.")
    if "SIZE_BUDGET_MISMATCH" in fl:
        return out("ESCALATE", "R11-conflict", "Company size and stated budget conflict by orders of magnitude, so the budget field is probably wrong on a potentially large account.",
                   0.75, "sales-lead", "Confirm budget and scope with the contact.")
    if b is None:
        why = {"BUDGET_NEGATIVE": "negative", "BUDGET_NOT_NUMERIC": "non-numeric", "BUDGET_MISSING": "missing"}
        k = next((x for x in why if x in fl), "BUDGET_MISSING")
        return out("NURTURE", "R12-budget-unclear", f"Budget is {why[k]}, so qualification is not possible yet; educate and ask for a range.",
                   0.6, "", "Send pricing-education sequence and ask for a monthly range.")
    if "REPEAT_CONTACT_CONFLICT" in fl:
        dec = "ESCALATE" if b >= QUALIFY_MIN_BUDGET else "NURTURE"
        return out(dec, "R14-repeat-conflict", f"Same email as {ref} but a different profile and story; verify who this is before investing.",
                   0.55, "sdr", "Verify identity on a short call.")
    if f["words"] < MIN_NEED_WORDS:
        return out("NURTURE", "R15-no-need", "Budget and company look fine but no need is stated; ask what they want before sales time is spent.",
                   0.6, "", "Send a one-question discovery reply.")
    if b < QUALIFY_MIN_BUDGET:
        return out("NURTURE", "R16-below-threshold", f"Stated need is real but budget is below the ${QUALIFY_MIN_BUDGET:,}/month qualification line; nurture toward a later start.",
                   0.8, "", "Light-touch nurture; revisit when budget changes.")
    note = " (non-English; route to a speaker)" if any(x.startswith("LANG_") for x in fl) else ""
    return out("QUALIFY", "R17-qualify", f"Clear need, budget at or above ${QUALIFY_MIN_BUDGET:,}/month and a verifiable company{note}.",
               0.85, "sales-lead", "Book a discovery call.")


def run(rows, reader=None):
    feats = [featurize(r) for r in rows]
    dedupe(rows, feats)
    results, trace = [], []
    for r, f in zip(rows, feats):
        d = decide(r, f)
        rd = (reader or {}).get(r["lead_id"])
        if rd and d["decision"] == "QUALIFY" and rd != "QUALIFY":
            # one-way ratchet: the independent LLM reader may only make the outcome MORE cautious.
            # Only its label is used (never its free text), so nothing it echoes can leak into outputs.
            f["flags"].add("READER_DISAGREES")
            d = {"decision": "ESCALATE", "rule": "R99-reader-ratchet",
                 "reason": f"Rules engine would qualify but the independent LLM reader said {rd}; a human adjudicates the disagreement.",
                 "confidence": min(d["confidence"], 0.6), "route_to": "sales-lead",
                 "next_action": "Read the reader trace in logs/ and decide."}
        d.update({"lead_id": r["lead_id"], "flags": sorted(f["flags"]), "merge_into": f.get("dup_of", "")})
        results.append(d)
        trace.append({"lead_id": r["lead_id"], "row_sha": sha(json.dumps(r, sort_keys=True)),
                      "budget_parsed": f["budget"], "flags": sorted(f["flags"]),
                      "rule": d["rule"], "decision": d["decision"], "confidence": d["confidence"]})
    return results, trace


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--out", default="out")
    ap.add_argument("--reader", default=None)
    a = ap.parse_args(argv)
    raw = Path(a.csv).read_bytes()
    print(f"triage {VERSION} | input={a.csv} | sha256={hashlib.sha256(raw).hexdigest()}")
    rows = list(csv.DictReader(raw.decode("utf-8").splitlines(), skipinitialspace=False))
    reader = ({x["lead_id"]: x["decision"] for x in json.loads(Path(a.reader).read_text())}
              if a.reader else None)
    results, trace = run(rows, reader)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cols = ["lead_id", "decision", "reason", "confidence", "flags", "rule", "route_to", "next_action", "merge_into"]
    with open(out / "decisions.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for d in results:
            w.writerow([";".join(d[c]) if c == "flags" else d[c] for c in cols])
    (out / "decisions.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
    (out / "trace.jsonl").write_text("\n".join(json.dumps(t, ensure_ascii=False) for t in trace) + "\n")
    for d in results:
        print(f"{d['lead_id']:>5}  {d['decision']:<8} {d['confidence']:.2f}  {d['rule']:<20} {','.join(d['flags'])}")
    from collections import Counter
    print("summary:", dict(Counter(d["decision"] for d in results)), f"rows={len(results)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
