"""master_detector.py: heuristic phishing scoring and sample email generator."""

import random
import re
import string
from datetime import datetime
from email import message_from_string
from email.header import decode_header, make_header
from urllib.parse import urlparse

URGENCY = ["act now", "act immediately", "urgent action required", "verify your account",
           "your account will be suspended", "account suspended", "confirm your identity",
           "unusual activity", "unauthorized access", "immediate action", "final notice",
           "response required", "limited time", "within 24 hours", "within 48 hours",
           "before it's too late", "avoid suspension", "account locked", "security alert",
           "your account has been compromised", "click below to restore access"]
CREDENTIALS = ["confirm your password", "enter your password", "verify your password",
               "update your billing information", "confirm your credit card",
               "provide your social security number", "enter your pin",
               "re-enter your login details", "validate your account information",
               "confirm your bank details", "verify your ssn", "your login credentials"]
GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear account holder",
             "dear sir/madam", "dear member", "hello customer", "valued client"]
REWARDS = ["you have won", "claim your prize", "you are a winner", "free gift",
           "you've been selected", "congratulations you", "claim your reward",
           "exclusive offer just for you", "lottery winner"]
BAD_TLDS = (".zip", ".mov", ".xyz", ".top", ".club", ".work", ".click", ".gq", ".tk",
            ".ml", ".cf", ".ga", ".icu", ".loan", ".men", ".download")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at"}
ATTACHMENTS = [".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".html attachment",
               "invoice.zip", "invoice.exe", "document.exe"]
BRANDS = {
    "paypal": ["paypal.com"], "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "google": ["google.com", "gmail.com"], "amazon": ["amazon.com"],
    "netflix": ["netflix.com"], "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"], "chase": ["chase.com"],
    "facebook": ["facebook.com", "fb.com"], "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"], "irs": ["irs.gov"], "sars": ["sars.gov.za"],
}

# What the user should actually do, per finding
ACTIONS = {
    "credentials": "Do not type your password, PIN or card details anywhere this email points you. If you already did, change that password now and turn on two-factor authentication.",
    "brand_impersonation": "Do not use the links in this email. Open the {brand} app you already have installed, or call {brand} on the number printed on your card or bill, and check your account that way.",
    "display_name_spoof": "Do not reply to this sender. Call {brand} on the number printed on your card or bill.",
    "reply_mismatch": "Do not hit Reply. Replies would go to a different address than the one shown as the sender.",
    "ip_link": "Do not open the link. Real companies do not send links made of numbers only.",
    "shortener": "Do not click the shortened link. Ask the sender to tell you what it is for, using a phone number you already have for them.",
    "suspicious_tld": "Do not visit the link. Its web address ending is common on throwaway scam sites.",
    "link_mismatch": "Do not click the link. What it displays is not where it goes. Hover over it to see the real address.",
    "attachment": "Do not download or open the attachment. If you expected a file, ask the sender to resend it through a channel you trust.",
    "urgency": "Ignore the deadline. If you are worried about the account, open the company's app or call the number on your card or bill, never use this email.",
    "reward_bait": "Do not claim the prize. Genuine rewards do not arrive by surprise email.",
    "generic_greeting": "Check whether the company usually greets you by name. Banks and shops you use normally do.",
}
HEADLINES = {
    "Critical": "This is almost certainly phishing. Do not click, reply or download anything. Report it as phishing (in Gmail: the three dots menu, then Report phishing) and delete it. If it came to a work address, forward it to your IT or security team first.",
    "High": "This is very likely phishing. Do not click, reply or download anything. Report it as phishing and delete it.",
    "Medium": "This email has suspicious traits. Do not click any links yet. Confirm it is real by calling the sender on a phone number you already have, not one from this email.",
    "Low": "No strong warning signs were found. If the email asks for money, a login or a payment, confirm it with the sender through a separate channel before acting.",
}


def _domain(text):
    """Domain of a URL or an email address ('' if none)."""
    text = text.strip()
    if re.match(r"(https?://|www\.)", text, re.I):
        return urlparse(text if "//" in text else "//" + text).netloc.lower().split("@")[-1]
    m = re.search(r"@([\w.-]+)", text)
    return m.group(1).lower() if m else ""


def _decode(value):
    try:
        return str(make_header(decode_header(value or ""))).strip()
    except Exception:
        return (value or "").strip()


def _parse(raw):
    """Return (headers, body, scan_text). Handles raw .eml/'Show original'
    emails and text copied straight from the Gmail message view."""
    msg = message_from_string(raw.strip())
    if msg.get("From") or msg.get("Subject"):
        headers = {k: _decode(msg.get(k)) for k in ("From", "Reply-To", "Subject")}
        parts = []
        for part in msg.walk():
            if part.get_content_maintype() == "text":
                payload = part.get_payload(decode=True)
                if payload:
                    parts.append((part.get_content_subtype(),
                                  payload.decode(part.get_content_charset() or "utf-8", "ignore")))
        scan = "\n".join(p for _, p in parts) or raw
        plain = [p for kind, p in parts if kind == "plain"]
        body = "\n".join(plain) if plain else re.sub(r"<[^>]+>", " ", scan)
        return headers, body.strip(), scan

    # Gmail paste: subject line, then "Name <address>", "to me", date, body
    lines = [l.strip() for l in raw.splitlines()]
    headers = {"From": "", "Reply-To": "", "Subject": ""}
    for i, line in enumerate(lines[:12]):
        if re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", line):
            headers["From"] = line
            headers["Subject"] = next((l for l in lines[:i] if l and l.lower() not in ("inbox", "spam")), "")
            return headers, raw, raw
    return headers, raw, raw


def _flag(id, label, detail, weight, severity):
    return {"id": id, "label": label, "detail": detail, "weight": weight, "severity": severity}


class PhishingDetector:
    def analyze(self, raw_email):
        headers, body, scan = _parse(raw_email)
        sender, reply_to, subject = headers["From"], headers["Reply-To"], headers["Subject"]
        lower = f"{subject} {body}".lower()
        urls = re.findall(r"(?:https?://|www\.)[^\s)\]>\"']+", scan, re.I)
        url_domains = [_domain(u) for u in urls]
        flags, brand = [], "the company"

        hits = [p for p in URGENCY if p in lower]
        if hits:
            flags.append(_flag("urgency", "Urgency or pressure language",
                               f"Uses high-pressure phrasing such as “{hits[0]}” to rush the reader.",
                               min(20, 6 * len(hits[:3])), "high" if len(hits) > 1 else "medium"))
        hits = [p for p in CREDENTIALS if p in lower]
        if hits:
            flags.append(_flag("credentials", "Requests credentials or sensitive data",
                               f"Asks the reader to supply sensitive information (e.g. “{hits[0]}”).",
                               min(25, 12 * len(hits[:2])), "critical"))
        if any(g in lower for g in GREETINGS):
            flags.append(_flag("generic_greeting", "Generic greeting",
                               "Addresses the recipient generically instead of by name, typical of mass phishing.",
                               8, "low"))
        hits = [p for p in REWARDS if p in lower]
        if hits:
            flags.append(_flag("reward_bait", "Too-good-to-be-true reward",
                               f"Dangles an unexpected prize or reward (e.g. “{hits[0]}”) to prompt a click.",
                               15, "high"))

        sender_dom, reply_dom = _domain(sender), _domain(reply_to)
        if sender_dom and reply_dom and sender_dom != reply_dom:
            flags.append(_flag("reply_mismatch", "Reply-To doesn't match sender",
                               f"Replies go to “{reply_dom}” while the message claims to be from “{sender_dom}”.",
                               18, "high"))

        # Brand impersonation: brand named, but sender or links are not on its real domains
        for name, real in BRANDS.items():
            if name in lower:
                for d in {sender_dom, *url_domains} - {""}:
                    if not any(d == r or d.endswith("." + r) for r in real):
                        brand = name.title()
                        flags.append(_flag("brand_impersonation", "Possible brand impersonation",
                                           f"Mentions “{brand}” but links/sender point to “{d}”, not an official {brand} domain.",
                                           22, "critical"))
                        break
                break

        if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", scan):
            flags.append(_flag("ip_link", "Link uses a raw IP address",
                               "Contains a link that points to a bare numeric IP address instead of a normal domain.",
                               20, "critical"))
        short = next((d for d in url_domains if d in SHORTENERS), None)
        if short:
            flags.append(_flag("shortener", "URL shortener detected",
                               f"Uses a link shortener ({short}) which hides the true destination.", 12, "medium"))
        tld = next((d for d in url_domains if d.endswith(BAD_TLDS)), None)
        if tld:
            flags.append(_flag("suspicious_tld", "Uncommon / high-risk domain ending",
                               f"Link domain “{tld}” uses a top-level domain often abused for throwaway phishing sites.",
                               14, "medium"))
        for href, shown in re.findall(r'href=["\']([^"\']+)["\'][^>]*>([^<]{3,40})<', scan, re.I):
            if shown.strip().lower().startswith(("http", "www")) and _domain(shown) != _domain(href):
                flags.append(_flag("link_mismatch", "Link text doesn't match its destination",
                                   f"Displayed link text “{shown.strip()}” does not match where it actually points.",
                                   20, "critical"))
                break

        if any(h in lower for h in ATTACHMENTS):
            flags.append(_flag("attachment", "References a risky attachment type",
                               "Mentions an executable or script-type attachment, a common malware delivery method.",
                               18, "high"))
        text = f"{subject} {body}"
        if re.search(r"!{2,}", text) or len(re.findall(r"[A-Z]{6,}", text)) >= 2:
            flags.append(_flag("shouting", "Excessive punctuation or capitalization",
                               "Uses repeated exclamation marks or blocks of capital letters to create alarm.",
                               6, "low"))

        # Display name claims a brand but the address is elsewhere
        m = re.match(r'\s*"?([^"<]+)"?\s*<([^>]+)>', sender)
        if m:
            shown, addr = m.group(1).strip(), m.group(2).strip().lower()
            for name, real in BRANDS.items():
                if name in shown.lower() and not any("@" + r in addr for r in real):
                    brand = name.title()
                    flags.append(_flag("display_name_spoof", "Display name impersonates a brand",
                                       f"Sender is shown as “{shown}” but the actual address is “{addr}”.",
                                       20, "critical"))
                    break

        score = min(100, sum(f["weight"] for f in flags)) or 2
        level = "Critical" if score >= 70 else "High" if score >= 45 else "Medium" if score >= 20 else "Low"
        flags.sort(key=lambda f: -f["weight"])
        actions = [ACTIONS[f["id"]].format(brand=brand) for f in flags if f["id"] in ACTIONS]
        return {
            "score": score, "risk_level": level, "flags": flags, "urls": urls,
            "sender": sender or "Unknown sender", "subject": subject or "No subject",
            "reply_to": reply_to, "recommendation": HEADLINES[level], "actions": actions,
            "analyzed_at": datetime.now().isoformat(timespec="seconds"),
        }

    # Sample generation

    PHISH = [
        ("PayPal", "paypal-secure-verify.com", "Your account has been limited",
         "Dear Customer,\n\nWe noticed unusual activity on your PayPal account. Your account has been temporarily limited until we can verify your identity.\n\nTo restore full access, please confirm your password and billing information within 24 hours by clicking the secure link below:\n\nhttps://{domain}/restore-access?id={token}\n\nIf you do not verify your account, it will be permanently suspended.\n\nThank you,\nPayPal Security Team"),
        ("Microsoft", "microsoft-office365-alert.top", "Security alert: unusual sign-in activity",
         "Dear User,\n\nWe detected an unauthorized access attempt on your Microsoft 365 account from an unrecognized device.\n\nFor your protection, we have locked your account. Verify your identity immediately to avoid permanent suspension:\n\nhttps://{domain}/verify?ref={token}\n\nFailure to respond within 24 hours will result in account closure.\n\nMicrosoft Account Team"),
        ("DHL", "dhl-parcel-tracking.xyz", "Your parcel could not be delivered",
         "Dear Customer,\n\nOur courier attempted to deliver your parcel but a small customs fee of $2.99 is outstanding.\n\nClick below to pay the fee and reschedule delivery within 48 hours, or your parcel will be returned to sender:\n\nhttps://{domain}/pay-fee/{token}\n\nDHL Express Support"),
        ("Bank of America", "boa-online-secure.club", "Final notice: verify your account information",
         "Dear Account Holder,\n\nWe were unable to verify your recent account information. Please confirm your card number, PIN and social security number to avoid a hold on your funds.\n\nVerify now: https://{domain}/secure-login/{token}\n\nThis is your final notice before restriction.\n\nBank of America Online Security"),
        ("IT Helpdesk", "corp-mail-helpdesk.work", "Action required: your mailbox is almost full",
         "Hello,\n\nYour mailbox has exceeded its storage limit and incoming mail is being rejected. Click below and sign in with your current email credentials to increase your quota immediately:\n\nhttps://{domain}/upgrade-mailbox?u={token}\n\nIT Helpdesk"),
    ]
    LEGIT = [
        ("GitHub", "github.com", "[GitHub] A new SSH key was added to your account",
         "Hi there,\n\nA new SSH key was recently added to your account.\n\nKey name: work-laptop\nAdded on: {date}\n\nIf this was you, no action is needed. If you don't recognize this activity, please review your security settings at https://github.com/settings/security.\n\nThanks,\nThe GitHub Team"),
        ("Google", "google.com", "Your monthly Google Drive storage summary",
         "Hi,\n\nHere's a quick summary of your Google Drive usage for this month.\n\nStorage used: 8.2 GB of 15 GB\n\nManage your storage anytime at https://drive.google.com/settings/storage.\n\nThe Google Drive Team"),
        ("Amazon", "amazon.com", "Your order has shipped",
         "Hello,\n\nGood news, your recent order has shipped and is on its way.\n\nYou can track your package anytime from Your Orders at https://www.amazon.com/gp/css/order-history.\n\nThanks for shopping with us,\nAmazon"),
        ("A colleague", "yourcompany.com", "Notes from today's planning meeting",
         "Hi team,\n\nThanks for joining today's planning session. I've attached the agenda recap below and will send the follow-up doc tomorrow.\n\nKey action items:\n- Finalize Q3 roadmap draft\n- Review budget with finance\n\nLet me know if I missed anything.\n\nBest,\nSam"),
        ("LinkedIn", "linkedin.com", "You appeared in 12 searches this week",
         "Hi,\n\nYour profile appeared in 12 searches this week. See who's viewing your profile at https://www.linkedin.com/me/profile-views.\n\nThe LinkedIn Team"),
    ]

    @staticmethod
    def _token(n=10):
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def generate_sample(self, category="phishing"):
        phishing = category.lower() == "phishing"
        brand, domain, subject, body = random.choice(self.PHISH if phishing else self.LEGIT)
        body = body.format(domain=domain, token=self._token(), date=datetime.now().strftime("%b %d, %Y"))
        if phishing:
            sender, reply_to = f'"{brand} Security" <no-reply@{domain}>', f"support@{self._token(6)}-mail.ru"
        else:
            sender, reply_to = f'"{brand}" <notifications@{domain}>', f"notifications@{domain}"
        raw = f"From: {sender}\nTo: you@example.com\nSubject: {subject}\nReply-To: {reply_to}\n\n{body}"
        return {"category": "phishing" if phishing else "legitimate", "brand": brand, "subject": subject,
                "from": sender, "reply_to": reply_to, "body": body, "raw": raw}

    def generate_batch(self, n_phishing=3, n_legit=3):
        samples = [self.generate_sample("phishing") for _ in range(n_phishing)]
        samples += [self.generate_sample("legitimate") for _ in range(n_legit)]
        random.shuffle(samples)
        return samples