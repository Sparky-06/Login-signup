from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from secret_key import create_load_key
import re
import secrets

# --- Initialization ---
app = Flask(__name__)
CORS(app)

key = create_load_key()
f = Fernet(key)

# In-memory "database" for demonstration
# NOTE: This resets every time the serverless function restarts
user_data = []


# --- Helper functions ---
def encrypt(password):
    return f.encrypt(password.encode()).decode()

def decrypt(password):
    return f.decrypt(password.encode()).decode()


# --- Routes ---

# Add a new route for /welcome
@app.route("/welcome")
def welcome():
    return "<h1>Hello guys</h1>"


@app.route("/api/signup", methods=["POST"])
def signup():
    input_details = request.get_json()
    input_details = {k: v.strip() if isinstance(v, str) else v for k, v in input_details.items()}

    required_fields = ["username", "password", "name", "email", "phone"]
    if not all(field in input_details for field in required_fields):
        return jsonify({"error": "Input must contain all details (name, username, email, phone, password)"}), 400

    # Validate email and phone
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", input_details["email"]):
        return jsonify({"error": "Email address is invalid"}), 400

    if not re.match(r"^[1-9]\d{9}$", input_details["phone"]):
        return jsonify({"error": "Enter valid 10-digit phone number"}), 400

    # Check duplicate username
    if any(u["username"].lower() == input_details["username"].lower() for u in user_data):
        return jsonify({"error": "Username already exists"}), 400

    # Encrypt password and save user
    encrypted_pw = encrypt(input_details["password"])
    user_data.append({
        "name": input_details["name"],
        "username": input_details["username"],
        "email": input_details["email"],
        "phone": input_details["phone"],
        "password": encrypted_pw,
        "status": "registered"
    })

    return jsonify({"message": "Signed up successfully"}), 201


@app.route("/api/login", methods=["POST"])
def login():
    input_data = request.get_json()
    if "username" not in input_data or "password" not in input_data:
        return jsonify({"Error": "Missing username or password"}), 400

    for user in user_data:
        if user["username"] == input_data["username"]:
            if decrypt(user["password"]) == input_data["password"]:
                if "token" in user:
                    return jsonify({"Error": "User already logged in"}), 409

                token = secrets.token_hex(32)
                user["token"] = token

                # Redirect to /welcome page after successful login
                return redirect(url_for("welcome"))

            return jsonify({"Error": "Incorrect password"}), 404

    return jsonify({"Error": "Username not found"}), 404



@app.route("/api/logout", methods=["PUT"])
def logout():
    input_data = request.get_json()

    for user in user_data:
        if user["username"] == input_data.get("username"):
            if "token" not in input_data:
                return jsonify({"Error": "Pass user token for logging out"}), 400

            try:
                if user["token"] == decrypt(input_data["token"]):
                    del user["token"]
                    return jsonify({"Message": f"Logged out for {user['username']}"}), 200
            except Exception:
                return jsonify({"Error": "Token error / user already logged out"}), 400

    return jsonify({"Error": "Incorrect username"}), 404


# --- Do NOT include app.run() ---
# Vercel automatically uses the "app" object
