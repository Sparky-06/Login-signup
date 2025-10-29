from flask import Flask, request, jsonify, redirect, url_for
from flask_cors import CORS
from cryptography.fernet import Fernet
from secret_key import create_load_key
import re
import secrets
import os
#from dotenv import load_dotenv                      #LOCALLY
from supabase import create_client, Client

# --- Initialization ---
app = Flask(__name__)
CORS(app)

key = create_load_key()
f = Fernet(key)

#load_dotenv()    #LOCALLY


url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)


# In-memory "database" for demonstration
# NOTE: This resets every time the serverless function restarts
def user_data():
    response = (supabase.table("user_data").select("*").execute())
    return response.data


# --- Helper functions ---
def encrypt(password):
    return f.encrypt(password.encode()).decode()

def decrypt(password):
    return f.decrypt(password.encode()).decode()


# --- Routes ---
@app.route("/api/signup", methods=["POST"])
def signup():
    data = user_data()
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
    if any(u["username"].lower() == input_details["username"].lower() for u in data):
        return jsonify({"error": "Username already exists"}), 400

    # Encrypt password and save user
    encrypted_pw = encrypt(input_details["password"])
    
    
    response = (supabase.table("user_data").insert({"name": input_details["name"],
        "username": input_details["username"],
        "email": input_details["email"],
        "phone": input_details["phone"],
        "password": encrypted_pw,
        "status": "registered"}).execute()
        )

    return jsonify({"message": "Signed up successfully"}), 201




@app.route("/welcome", methods = ['GET'])
def welcome():
    return "<h1>Surprise babydoll!</h1>"




@app.route("/api/login", methods=["POST"])
def login():
    data = user_data()
    input_data = request.get_json()
    if "username" not in input_data or "password" not in input_data:
        return jsonify({"Error": "Missing username or password"}), 400

    for user in data:
        if user["username"] == input_data["username"]:
            if decrypt(user["password"]) == input_data["password"]:
                response = (supabase.table("user_data").select("token").eq("username", input_data["username"]).execute())
                if response.data and response.data[0].get("token"):
                    #return jsonify({"error": "User already logged in"}), 409
                    existing_token = response.data[0]["token"]
                    return jsonify({"message": "Logged in successfully", "token": existing_token}), 200

                token = secrets.token_hex(32)
                response = (supabase.table("user_data").update({"token": token}).eq("username", input_data['username']).execute())

#No token encryption here!!!

                # Redirect to /welcome page after successful login
                return jsonify({"message": "Logged in successfully", "token": token}), 200
                #return redirect("https://www.youtube.com/")

            return jsonify({"Error": "Incorrect password"}), 404

    return jsonify({"Error": "Username not found"}), 404



@app.route("/api/logout", methods=["PUT"])
def logout():
    data = user_data()
    input_data = request.get_json()

    for user in data:
        if user["username"] == input_data["username"]:
            if "token" not in input_data:
                return jsonify({"Error": "Pass user token for logging out"}), 400

            try:
                if user["token"] == input_data["token"]:
                    response = supabase.table('user_data').update({'token': None}).eq('username', user['username']).execute()
                    return jsonify({"Message": f"Logged out for {user['username']}"}), 200
            except Exception:
                return jsonify({"Error": "Token error / user already logged out"}), 400

    return jsonify({"Error": "Incorrect username"}), 404




if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, ssl_context='adhoc', debug=True)






