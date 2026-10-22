"""URL and message analysis with explainable heuristic indicators."""
from __future__ import annotations
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit
import joblib

class URLFeatureExtractor:
    """Extract straightforward URL signals; none alone proves abuse."""
    SUSPICIOUS_TLDS = {"xyz", "top", "tk"}

    def extract(self, url: str) -> tuple[dict[str, object], list[str], float]:
        raw = url.strip()
        candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else f"//{raw}"
        try:
            parts = urlsplit(candidate)
            host = (parts.hostname or "").lower().rstrip(".")
            port = parts.port
        except ValueError:
            parts, host, port = urlsplit(""), "", None
        indicators: list[str] = []
        score = 0.0
        def flag(condition: bool, label: str, weight: float) -> None:
            nonlocal score
            if condition:
                indicators.append(label)
                score += weight
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
        except ValueError:
            is_ip = False
        labels = host.split(".") if host else []
        tld = labels[-1] if len(labels) > 1 else ""
        flag(len(raw) >= 75, f"Long URL ({len(raw)} characters)", 12)
        flag("@" in raw, "'@' symbol may obscure the destination", 20)
        flag(is_ip, "IP address used instead of a domain", 25)
        flag(len(labels) >= 5, "Many subdomains", 12)
        flag("-" in (labels[-2] if len(labels) >= 2 else host), "Hyphen in domain name", 8)
        flag(tld in self.SUSPICIOUS_TLDS, f"Uncommon high-risk TLD (.{tld})", 15)
        flag(port is not None and port not in (80, 443), f"Non-standard port ({port})", 12)
        is_https = parts.scheme.lower() == "https"
        flag(bool(host) and not is_https, "URL does not use HTTPS", 10)
        flag(any(term in raw.lower() for term in ("login", "verify", "secure", "update", "account")),
             "Credential or account-related wording in URL", 8)
        return ({"length": len(raw), "host": host, "https": is_https, "uses_ip": is_ip,
                 "subdomain_count": max(0, len(labels) - 2), "port": port}, indicators, min(score, 100.0))

class PhishingClassifier:
    """Analyze a URL or message and return a score with its indicator breakdown."""
    URGENCY = ("immediate action", "verify account", "suspended", "urgent", "final warning",
               "act now", "expires today", "unusual activity")
    CTA = ("click here", "click now", "login here", "sign in", "confirm your password",
           "update billing", "enter your password", "reply with your password")
    BRAND = ("paypal", "microsoft", "google", "apple", "amazon", "bank", "netflix")

    def __init__(self, model_path: str | Path | None = None):
        self.extractor = URLFeatureExtractor()
        path = Path(model_path) if model_path else Path(__file__).resolve().parent / "message_model.joblib"
        self.model = joblib.load(path) if path.exists() else None

    def analyze(self, text_or_url: str) -> dict[str, object]:
        text = (text_or_url or "").strip()
        if not text:
            raise ValueError("Enter a URL or message to analyze.")
        indicators: list[str] = []
        url_score = 0.0
        urls = re.findall(r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9-]+\.[a-z]{2,}(?:/[^\s<>\"']*)?", text, re.I)
        for url in urls[:5]:
            _, found, risk = self.extractor.extract(url.rstrip(".,);]"))
            indicators.extend(found)
            url_score = max(url_score, risk)
        lower = text.lower()
        heuristic_score = 0.0
        for term in self.URGENCY:
            if term in lower:
                indicators.append(f"Urgency or threat language: '{term}'")
                heuristic_score += 12
        for term in self.CTA:
            if term in lower:
                indicators.append(f"Suspicious call to action: '{term}'")
                heuristic_score += 10
        for brand in self.BRAND:
            if brand in lower and any(x in lower for x in ("verify", "password", "suspended", "login", "locked")):
                indicators.append(f"Brand name paired with an account/security request: '{brand}'")
                heuristic_score += 12
                break
        model_score = 0.0
        if self.model is not None and not urls:
            probabilities = self.model.predict_proba([text])[0]
            classes = list(self.model.classes_)
            if 1 in classes:
                model_score = float(probabilities[classes.index(1)]) * 100
        if urls:
            score = 0.55 * url_score + 0.35 * min(heuristic_score, 60) + 0.10 * model_score
        else:
            score = 0.55 * min(heuristic_score, 100) + 0.45 * model_score if self.model else min(heuristic_score, 100)
        score = round(max(0.0, min(100.0, score)), 1)
        classification = "High-Risk Phishing" if score >= 70 else "Suspicious" if score >= 35 else "Legitimate"
        return {"risk_score": score, "classification": classification,
                "indicators": list(dict.fromkeys(indicators)),
                "details": {"url_risk": round(url_score, 1), "heuristic_risk": round(min(heuristic_score, 100), 1),
                            "model_risk": round(model_score, 1), "urls_found": len(urls),
                            "model_loaded": self.model is not None}}
