import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from shield import (extract_urls, analyze_url, analyze_language, compute_score, rule_verdict,
                    registered_domain)


def issues(u):
    return " | ".join(i for i, _ in analyze_url(u))


def test_extract_urls_strips_punctuation():
    assert extract_urls("see http://a.com/x, and www.b.org.") == ["http://a.com/x", "www.b.org"]


def test_ip_host():
    assert "raw IP" in issues("http://192.168.1.5/login")


def test_digit_swap_brand():
    assert "look-alike of 'paypal'" in issues("https://paypa1.com/login")


def test_brand_impersonation():
    assert "impersonates 'sbi'" in issues("http://sbi-kyc-update.top/login")


def test_genuine_domain_is_clean():
    assert analyze_url("https://www.google.com/search") == []
    assert analyze_url("https://drive.google.com/drive/folders/x") == []


def test_shortener():
    assert "shortener" in issues("https://bit.ly/abc")


def test_registered_domain():
    assert registered_domain("mail.sbi.co.in") == "sbi.co.in"


def test_language_and_sender_mismatch():
    msgs = analyze_language("URGENT: verify your account with your OTP, Amazon support", "help@random-mail.xyz")
    assert any("urgency" in m for m in msgs) and any("does not match" in m for m in msgs)


def test_score_and_verdict():
    links = [{"url": "u", "issues": analyze_url("http://192.168.1.5/sbi")}]
    lang = analyze_language("urgent verify your account otp")
    assert rule_verdict(compute_score(links, lang)) == "PHISHING"
    assert rule_verdict(compute_score([], [])) == "SAFE"
