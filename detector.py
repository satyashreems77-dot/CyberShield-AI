import re
from url_checker import check_url


def analyze_message(message):
    text = message.lower().strip()

    score = 0
    reasons = []
    # URL analysis
    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text)

    for url in urls:
        url_result = check_url(url)

        score += url_result["score"]

        for warning in url_result["warnings"]:
            reasons.append("URL check: " + warning)

    # 1. Sensitive information
    sensitive_words = [
        "otp", "password", "pin", "cvv",
        "verification code", "security code"
    ]

    if any(word in text for word in sensitive_words):
        score += 30
        reasons.append(
            "The message asks for sensitive information such as OTP, PIN, password or CVV."
        )

    # 2. Urgency or threats
    urgent_words = [
        "urgent", "immediately", "act now",
        "within 24 hours", "account will be blocked",
        "account suspended", "last warning"
    ]

    if any(word in text for word in urgent_words):
        score += 20
        reasons.append(
            "The message uses urgency or threats to pressure the user."
        )

    # 3. Prize / reward
    prize_words = [
        "you won", "winner", "lottery",
        "prize", "reward", "cash prize",
        "free money", "congratulations"
    ]

    if any(word in text for word in prize_words):
        score += 20
        reasons.append(
            "The message contains a possible fake prize or reward claim."
        )

    # 4. Suspicious link
    if re.search(r"https?://|www\.", text):
        
        reasons.append(
            "The message contains a web link. Verify the website before opening it."
        )

    # 5. Banking / payment
    banking_words = [
        "bank", "upi", "credit card",
        "debit card", "account number",
        "transaction", "payment"
    ]

    if any(word in text for word in banking_words):
        score += 15
        reasons.append(
            "The message involves banking, payment or financial information."
        )

    # 6. Free / unbelievable offers
    offer_words = [
        "free iphone", "free gift",
        "claim now", "limited offer",
        "special offer"
    ]

    if any(word in text for word in offer_words):
        score += 15
        reasons.append(
            "The message contains an unusually attractive or time-limited offer."
        )
    # 7. Combination risk signals
    if any(word in text for word in banking_words) and re.search(r"https?://|www\.", text):
        score += 15
        reasons.append(
        "The message combines financial information with a web link, which can indicate a phishing attempt."
    )

    if any(word in text for word in sensitive_words) and any(word in text for word in urgent_words):
        score += 15
        reasons.append(
            "The message combines a sensitive information request with urgency, which is a strong phishing signal."
        )

    if any(word in text for word in prize_words) and re.search(r"https?://|www\.", text):
        score += 15
        reasons.append(
            "A prize or reward claim combined with a web link is a common scam pattern."
        )

    if any(word in text for word in banking_words) and any(word in text for word in sensitive_words):
        score += 15
        reasons.append(
            "The message combines financial information with a request for sensitive credentials."
        )

    if "click" in text and re.search(r"https?://|www\.", text):
        score += 10
        reasons.append(
            "The message asks the user to click a link, increasing the risk of phishing."
        )
    # Maximum score
    score = min(score, 100)

    # Threat level
    if score >= 70:
        threat = "🔴 HIGH RISK"
    elif score >= 40:
        threat = "🟠 MEDIUM RISK"
    elif score >= 20:
        threat = "🟡 LOW RISK"
    else:
        threat = "🟢 SAFE / LOW RISK"

    if not reasons:
        reasons.append(
            "No major suspicious patterns were detected in this message."
        )
        # Confidence level
    if score >= 70:
        confidence = "High"
        advice = "Do not click links or share OTP, passwords, PINs or banking details."
    elif score >= 40:
        confidence = "Medium"
        advice = "Be cautious. Verify the sender and avoid sharing sensitive information."
    elif score >= 20:
        confidence = "Low"
        advice = "The message has some suspicious signals. Verify before taking action."
    else:
        confidence = "Very Low"
        advice = "No major threat signals detected. Still avoid sharing sensitive information."

    return {
        "score": score,
        "threat": threat,
        "confidence": confidence,
        "advice": advice,
        "reasons": reasons
    }