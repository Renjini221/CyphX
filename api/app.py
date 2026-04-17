from flask import Flask,render_template,jsonify, request
import requests
import re
app=Flask(__name__)

apikey="AIzaSyAs0QrXFT8PesofAl6XjUKGHZ1wc9X8iDQ"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check",methods=["POST"])
def check():
    url = request.json.get("url")


    if not url.startswith("http"):
        url="http://"+url

    body={
        "client":{
            "clientId":"cyberCheck",
            "clientVersion":"1.0"
        },
        "threatInfo":{
            "threatTypes":["MALWARE","SOCIAL_ENGINEERING"],
            "platformTypes":["ANY_PLATFORM"],
            "threatEntryTypes":["URL"],
            "threatEntries":[{"url":url}]
        }
     }

    res=requests.post(
           f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apikey}",
           json=body
        )
    data = res.json()

    risk = 0

    domain = url.split("/")[2]
    vowels = sum(1 for c in domain if c in "aeiou")
    consonants = sum(1 for c in domain if c.isalpha() and c not in "aeiou")
    if consonants > 0 and vowels / (vowels + consonants)<0.25:
          risk += 2

    if len(domain) > 20:
          risk += 1
    if sum(c.isdigit() for c in domain)>3:
          risk += 1
                      
    if "matches" in data:
          return jsonify({"status":"danger","message":"Scam Btw"})
        
    if any(word in url for word in ["login","verify","bank","secure"]):
           risk=risk+2

    if len(url) > 30:
            risk+=1
    if "-" in url:
            risk+=1
    if risk>=2:
            return jsonify({"status":"suspicious","message":"its a suspicious website"})
    else:
            return jsonify({"status":"safe","message":"safe"})



