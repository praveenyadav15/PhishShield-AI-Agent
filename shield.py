"""Phish Shield - a LangGraph agent that investigates suspicious emails / SMS.

Graph:  extract -> links -> language -> score -> judge --(low confidence)--> judge (loop, max 2)
                                                   |--(phishing/suspicious)--> action -> END
                                                   `--(safe)----------------> clear  -> END
Works offline (rule engine only) when no Gemini key is set; Gemini adds reasoning + the action plan.
"""
import difflib
import json
import operator
import os
import re
from typing import Annotated, TypedDict
from urllib.parse import urlparse

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")

BRANDS = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "facebook", "instagram",
          "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "flipkart", "whatsapp", "linkedin"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
BAD_TLDS = {"zip", "top", "xyz", "click", "tk", "ml", "gq", "cf", "work", "support", "loan", "country", "icu"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})
LANG_RULES = {
    "urgency": ["urgent", "immediately", "within 24 hours", "suspended", "final notice", "act now",
                "expires today", "limited time", "last warning", "will be blocked", "will be closed"],
    "credential request": ["password", "otp", "cvv", "pin ", "card number", "net banking", "aadhaar",
                           "verify your account", "confirm your identity", "login to", "kyc"],
    "money lure": ["lottery", "you have won", "prize", "gift card", "refund", "claim your", "cashback",
                   "free iphone", "reward points"],
    "generic greeting": ["dear customer", "dear user", "dear sir/madam", "dear account holder"],
    "risky attachment": [".exe", ".scr", ".apk", ".zip attached", "enable macros"],
}


class State(TypedDict, total=False):
    raw: str
    sender: str
    urls: list
    link_findings: list
    language_findings: list
    rule_score: int
    verdict: str
    confidence: str
    reasoning: str
    attempts: int
    action_plan: str
    llm_used: bool
    trace: Annotated[list, operator.add]


# ---------- pure helper tools (unit-tested, no network) ----------
def extract_urls(text):
    found = re.findall(r"(?:https?://|www\.)[^\s<>\"')\]]+", text, flags=re.I)
    return list(dict.fromkeys(u.rstrip(".,;!?") for u in found))


def registered_domain(host):
    parts = host.lower().split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "ac", "gov"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze_url(url):
    """Return a list of (issue, weight) found in one URL."""
    u = url if "://" in url else "http://" + url
    p = urlparse(u)
    host = (p.hostname or "").lower()
    issues = []
    if p.scheme == "http":
        issues.append(("uses insecure http", 5))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        issues.append(("host is a raw IP address", 25))
    if "@" in p.netloc:
        issues.append(("'@' hides the real destination", 25))
    if "xn--" in host:
        issues.append(("punycode (look-alike characters)", 25))
    if registered_domain(host) in SHORTENERS:
        issues.append(("link shortener hides destination", 12))
    if host.rsplit(".", 1)[-1] in BAD_TLDS:
        issues.append((f"high-risk TLD .{host.rsplit('.', 1)[-1]}", 12))
    if host.count(".") >= 4:
        issues.append(("too many subdomains", 10))
    if host.count("-") >= 3:
        issues.append(("many hyphens in domain", 8))
    reg = registered_domain(host)
    label = reg.split(".")[0]
    for b in BRANDS:
        if reg == f"{b}.com" or reg.startswith(f"{b}.") and reg.count(".") == 1 and label == b:
            continue  # genuine-looking registered domain
        norm = label.translate(LEET)
        if b in host and label != b:
            issues.append((f"impersonates '{b}' (real domain is {reg})", 30))
            break
        if norm != label and norm == b:
            issues.append((f"digit-swap look-alike of '{b}'", 30))
            break
        if label != b and len(label) > 3 and difflib.SequenceMatcher(None, label, b).ratio() >= 0.84:
            issues.append((f"typo-squat of '{b}'", 30))
            break
    return issues


def analyze_language(text, sender=""):
    low = text.lower()
    out = [(cat, [k for k in kws if k in low]) for cat, kws in LANG_RULES.items()]
    out = [(c, hits) for c, hits in out if hits]
    msg = [f"{c}: {', '.join(h[:3])}" for c, h in out]
    if sender:
        sdom = registered_domain(sender.split("@")[-1].strip(" >"))
        for b in BRANDS:
            if b in low and b not in sdom:
                msg.append(f"sender domain '{sdom}' does not match brand '{b}' mentioned in message")
                break
    return msg


def compute_score(link_findings, language_findings):
    link = min(70, sum(w for f in link_findings for _, w in f["issues"]))
    lang = min(50, 10 * len(language_findings) + (10 if any("does not match" in m for m in language_findings) else 0))
    return min(100, link + lang)


def rule_verdict(score):
    return "PHISHING" if score >= 50 else "SUSPICIOUS" if score >= 20 else "SAFE"


# ---------- Gemini helper ----------
def _client():
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return None
    from google import genai
    return genai.Client(api_key=key)


def _llm(prompt, json_mode=False):
    from google.genai import types
    cfg = types.GenerateContentConfig(temperature=0.2,
                                      response_mime_type="application/json" if json_mode else None)
    return _client().models.generate_content(model=MODEL, contents=prompt, config=cfg).text


def _evidence(s):
    links = [f"{f['url']} -> " + "; ".join(i for i, _ in f["issues"]) for f in s.get("link_findings", []) if f["issues"]]
    return {"suspicious_links": links, "language_signals": s.get("language_findings", []),
            "rule_score_0_to_100": s.get("rule_score", 0), "sender": s.get("sender") or "unknown"}


# ---------- graph nodes ----------
def extract_node(s):
    urls = extract_urls(s["raw"])
    return {"urls": urls, "attempts": 0, "trace": [f"extract: found {len(urls)} URL(s)"]}


def links_node(s):
    findings = [{"url": u, "issues": analyze_url(u)} for u in s["urls"]]
    bad = sum(1 for f in findings if f["issues"])
    return {"link_findings": findings, "trace": [f"links: {bad}/{len(findings)} URL(s) look risky"]}


def language_node(s):
    msgs = analyze_language(s["raw"], s.get("sender", ""))
    return {"language_findings": msgs, "trace": [f"language: {len(msgs)} manipulation signal(s)"]}


def score_node(s):
    sc = compute_score(s["link_findings"], s["language_findings"])
    return {"rule_score": sc, "trace": [f"score: rule engine score = {sc}/100"]}


def judge_node(s):
    attempt = s.get("attempts", 0) + 1
    base = rule_verdict(s["rule_score"])
    if _client() is None:
        return {"verdict": base, "confidence": "medium", "attempts": attempt, "llm_used": False,
                "reasoning": "Offline mode (no API key): verdict from rule engine only.",
                "trace": [f"judge: offline rule verdict = {base}"]}
    strict = ("\nYour previous answer had LOW confidence. Re-check every evidence item one by one and "
              "decide firmly.") if attempt > 1 else ""
    prompt = (f"You are a cyber-security analyst. Message under review:\n---\n{s['raw'][:4000]}\n---\n"
              f"Automated evidence: {json.dumps(_evidence(s))}\n"
              'Reply ONLY JSON: {"verdict":"PHISHING|SUSPICIOUS|SAFE","confidence":"high|medium|low",'
              '"reasoning":"2-3 sentences citing the evidence"}' + strict)
    try:
        d = json.loads(_llm(prompt, json_mode=True))
        v = str(d.get("verdict", base)).upper()
        v = v if v in {"PHISHING", "SUSPICIOUS", "SAFE"} else base
        c = str(d.get("confidence", "medium")).lower()
        return {"verdict": v, "confidence": c, "reasoning": d.get("reasoning", ""), "attempts": attempt,
                "llm_used": True, "trace": [f"judge (attempt {attempt}): {v}, confidence {c}"]}
    except Exception as e:  # network / parsing problem -> degrade gracefully
        return {"verdict": base, "confidence": "medium", "attempts": attempt, "llm_used": False,
                "reasoning": f"LLM unavailable ({type(e).__name__}); using rule engine.",
                "trace": [f"judge: LLM failed, fallback rule verdict = {base}"]}


def route_after_judge(s):
    if s["confidence"] == "low" and s["attempts"] < 2:
        return "judge"
    return "action" if s["verdict"] in ("PHISHING", "SUSPICIOUS") else "clear"


FALLBACK_PLAN = ("1. Do NOT click any link, open attachments or reply.\n"
                 "2. Never share OTP, PIN, CVV or passwords - real companies never ask for them.\n"
                 "3. Open the official app/website by typing the address yourself to check for real alerts.\n"
                 "4. Report it: cybercrime.gov.in or helpline 1930 (India), or forward to your email provider's phishing address.\n"
                 "5. If you already clicked or paid: change passwords, call your bank immediately, enable 2-factor login.")


def action_node(s):
    plan = FALLBACK_PLAN
    if _client() is not None:
        try:
            plan = _llm(f"A message was classified {s['verdict']}. Evidence: {json.dumps(_evidence(s))}\n"
                        "Write a short numbered action plan (max 5 steps) for a non-technical user, specific to "
                        "this message. Mention reporting at cybercrime.gov.in / helpline 1930 if in India.")
        except Exception:
            pass
    return {"action_plan": plan, "trace": ["action: protection plan generated"]}


def clear_node(s):
    return {"action_plan": "No strong phishing signals found. Still: avoid sharing OTPs, and verify unexpected "
                           "requests through the official app or website.",
            "trace": ["clear: message looks safe"]}


def build_graph():
    from langgraph.graph import StateGraph, START, END
    g = StateGraph(State)
    for name, fn in [("extract", extract_node), ("links", links_node), ("language", language_node),
                     ("score", score_node), ("judge", judge_node), ("action", action_node), ("clear", clear_node)]:
        g.add_node(name, fn)
    g.add_edge(START, "extract")
    g.add_edge("extract", "links")
    g.add_edge("links", "language")
    g.add_edge("language", "score")
    g.add_edge("score", "judge")
    g.add_conditional_edges("judge", route_after_judge, {"judge": "judge", "action": "action", "clear": "clear"})
    g.add_edge("action", END)
    g.add_edge("clear", END)
    return g.compile()


def analyze(text, sender=""):
    return build_graph().invoke({"raw": text, "sender": sender})


if __name__ == "__main__":
    import sys
    r = analyze(sys.stdin.read())
    print(r["verdict"], r["rule_score"], "\n", r["reasoning"], "\n", r["action_plan"])
