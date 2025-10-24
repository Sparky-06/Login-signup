from flask import Flask, request, jsonify
import random
import os
import json
import re
from cryptography.fernet import Fernet
from secret_key import create_load_key
import secrets



key = create_load_key()
f = Fernet(key)


from flask_cors import CORS
app = Flask(__name__)
CORS(app)

DATA_FILE = 'user_data.json'


def get_data():
    if not os.path.exists(DATA_FILE):
        with open (DATA_FILE, 'w') as f:
            json.dump([], f)
    with open(DATA_FILE, 'r') as f:
        return json.load(f)
    
def add_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent = 4)




def encrypt(password):
    return f.encrypt(password.encode()).decode()


def decrypt(password):
    return f.decrypt(password.encode()).decode()





@app.route('/api/signup', methods=['POST'])
def signup():
    data = get_data()
    input_details = request.get_json()
    input_details = {k: v.strip() if isinstance(v, str) else v for k, v in input_details.items()}


    
    if 'username' not in input_details or 'password' not in input_details or 'name' not in input_details or 'email' not in input_details or 'phone' not in input_details:
        return jsonify({'error' : 'Input must contain all details (name, username, email, phone, password)'}), 400
    
    valid_mail = re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_details['email'])
    if not valid_mail:
          return jsonify({'error' : 'Email address is invalid'}), 400
    
    if not re.match(r'^[1-9]\d{9}$', input_details['phone']):
        return jsonify({'error': 'Enter valid 10-digit phone number'}), 400
      
    
    if any(ele['username'].lower() == input_details['username'].lower() for ele in data):
        return jsonify({'error': 'Username already exists'}), 400


    new_password = encrypt(input_details['password'])    
    data.append({'name' : input_details['name'], 'username' : input_details['username'], 'email' : input_details['email'],
                  'phone' : input_details['phone'], 'password' : new_password, 'status' : 'registered'})
    
    del new_password
    add_data(data)
    return jsonify({'message' : 'Signed up successfully'}), 201




@app.route('/api/login', methods = ['POST'])
def login():
    data = get_data()
    input_data = request.get_json()
    
    if 'username' not in input_data:
        return jsonify({'Error' : 'Missing username'}), 400

    if 'password' not in input_data:
        return jsonify({'Error':'Missing password'}), 400

    for ele in data:
        if ele['username'] == input_data['username']:
            password = decrypt(ele['password'])
            
            if input_data['password'] == password:
                if 'token' in ele:
                    del password
                    return jsonify({'Error' : 'User already logged in'}), 409
                
                token = secrets.token_hex(32)


                ele['token'] = token
                add_data(data)
                return jsonify({'Message' : 'Logged in successfully!', 'token' : encrypt(token)}), 200


            return jsonify({'Error' : 'Incorrect password'}), 404
        
    
    return jsonify({'Error' : 'Username not found'}), 404


@app.route('/api/logout', methods = ['PUT'])
def logout():
    data = get_data()
    input_data = request.get_json()

    for ele in data:
        if ele['username'] == input_data['username']:

            if 'token' not in input_data:
                return jsonify({'Error' : 'Pass user token for logging out'})

            try:
                if ele['token'] == decrypt(input_data['token']):
                    del ele['token']
                    add_data(data)
                    return jsonify({'Message' : "Logged out for " + ele['username']})
            except:
                return jsonify({"Error" : "Token error / user already logged out"})
            
    return jsonify({'Error' : 'Incorrect username'})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, ssl_context='adhoc', debug=True)