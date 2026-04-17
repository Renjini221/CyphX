from flask import Flask, render_template, jsonify, request
import requests
import os

app = Flask(__name__)

apikey = os.environ.get("apikey")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    url = request.json.get("url")

    if not url.startswith("http"):
        url = "http://" + url

    body = {
        "client": {"clientId": "cyberCheck", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    res = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apikey}",
        json=body
    )
    data = res.json()

    risk = 0

    domain = url.split("/")[2]
    vowels = sum(1 for c in domain if c in "aeiou")
    consonants = sum(1 for c in domain if c.isalpha() and c not in "aeiou")
    if consonants > 0 and vowels / (vowels + consonants) < 0.25:
        risk += 2

    if len(domain) > 20:
        risk += 1

    if sum(c.isdigit() for c in domain) > 3:
        risk += 1

    if risk >= 2:
        return jsonify({"status": "suspicious", "message": "Suspicious domain pattern detected"})

    if "matches" in data:
        return jsonify({"status": "danger", "message": "Flagged by Google Safe Browsing"})

    ai_res = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ.get('OPENROUTER_API_KEY')}",
            "Content-Type": "application/json"
        },
        json={
            "model": "mistralai/mistral-7b-instruct",
            "messages": [
                {
                    "role": "user",
                    "content": f"Is this URL a scam, phishing, or suspicious? Reply with only one word: safe, suspicious, or danger. URL: {url}"
                }
            ]
        },
        timeout=10
    )

    verdict = ai_res.json()["choices"][0]["message"]["content"].strip().lower()

    if "danger" in verdict:
        return jsonify({"status": "danger", "message": "AI flagged this as dangerous"})
    elif "suspicious" in verdict:
        return jsonify({"status": "suspicious", "message": "AI flagged this as suspicious"})
    else:
        return jsonify({"status": "safe", "message": "Looks safe"})
