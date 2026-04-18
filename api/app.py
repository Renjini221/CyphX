from flask import Flask, render_template, jsonify, request
import requests
import os
import difflib
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

apikey = os.environ.get("apikey")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    url = request.json.get("url")

    if not url.startswith("http"):
        url = "https://" + url

    domain = urlparse(url).netloc.replace("www.", "")
    risk = 0
    brands = ["amazon" , "google" , "paypal" , "facebook" , "instagram" , "netflix" , "insta" , "fb"]
    safe_domains = ["instagram.com" , "facebook.com","amazon.com" , "google.com" ,"paypal.com" , "netflix.com"]
    if domain not in safe_domains:
        for brand in brands:
            if brand in domain:
                risk += 3
            else:
                ratio = difflib.SequenceMatcher(None,brand,domain.split(".")[0]).ratio()    
                if ratio >0.6:
                    risk += 3
    if "login" in domain or "secure" in domain or "verify" in domain:
        risk +=1

    if len(domain) > 20:
        risk += 1

    if sum(c.isdigit() for c in domain) > 3:
        risk += 1

    heuristic_flag = risk >= 2
    
    whois_info={}
    try:
        whois_res=requests.get(
            f"https://whoisjson.com/api/v1/whois?domain={domain}",
            headers={"Authorization":f"TOKEN={os.environ.get('WHOIS_API_KEY')}"},
            timeout=10
        )
        whois_data = whois_res.json()
        created = whois_data.get("created","")
        expires = whois_data.get("expires","")
        registrar = whois_data.get("registrar","")
        country = whois_data.get("country","")

        age_days = None
        if created:
            try:
                created_date = datetime.strptime(created[:10],"%Y-%m-%d")
                age_days = (datetime.now() - created_date).days
            except:
                pass

        whois_info = {
                "created": created or "unknown",
                "expires": expires or "unknown",
                "registrar": registrar or "unknown",
                "country": country or "unknown",
                "age_days": age_days
            }   
        if age_days is not None and age_days < 30:
                return jsonify({
                    "status":"suspicious",
                    "message":f"Domain is only {age_days} days old",
                    "whois": whois_info
                })
    except:
          pass
    # 🔹 Google Safe Browsing
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

    if "matches" in data:
        return jsonify({"status": "danger", "message": "Flagged by Google Safe Browsing"})

    # 🔹 AI Check
    try:
        ai_res = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {os.environ.get('OPENROUTER_API_KEY')}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "user",
                        "content": f"""
Analyze this URL for phishing risk.

Only mark as "danger" if strong evidence exists.
If unsure, reply "safe".

Reply ONLY: safe, suspicious, or danger.

URL: {url}
"""
                    }
                ]
            },
            timeout=25
        )

        response_json = ai_res.json()

        if "choices" not in response_json:
            return jsonify({"status": "suspicious", "message": "AI error, proceed with caution"})

        verdict = response_json["choices"][0]["message"]["content"].strip().lower()

        # 🔥 FINAL LOGIC
        if "danger" in verdict:
            return jsonify({"status": "danger", "message": "AI flagged this as dangerous"})

        elif "suspicious" in verdict and heuristic_flag:
            return jsonify({"status": "suspicious", "message": "Looks suspicious"})

        elif heuristic_flag:
            return jsonify({"status": "suspicious", "message": "Suspicious pattern detected"})

        else:
            return jsonify({"status": "safe", "message": "Looks safe"})

    except Exception as e:
        return jsonify({"status": "suspicious", "message": "Error analyzing URL"})
 
