from flask import Flask,render_template,jsonify, request
import requests
app=Flask(__name__)
import os
apikey=os.environ.get("apikey")

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

    if data:
           return jsonify({"status":"danger","message":"Scam btw"})
        
    if any(word in url for word in ["login","verify","bank","secure"]):
           risk=risk+2

    if len(url) > 30:
            risk+=1
    if "-" in url:
            risk+=1
    if risk>=3:
            return jsonify({"status":"suspicious","message":"its a suspicious website"})
    else:
            return jsonify({"status":"safe","message":"safe"})

if __name__ == "__main__":
    app.run(debug=True)

