from flask import Flask, request, jsonify, send_from_directory, send_file, redirect
from flask_cors import CORS
import os, sys
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = Flask(__name__)
CORS(app)

ALERT_COLOR_BEG = "\033[91m"
LOG_COLOR_BEG = "\033[90m"
KEY_COLOR_BEG = "\033[93m"
DB_COLOR_BEG = "\033[92m"
COLOR_END = "\033[0m"



users = []
keys = []



with open("./kms/file_server_pubkey.pem", "rb") as f:
    pubkey_data = f.read()
    pubkey_key = serialization.load_pem_public_key(pubkey_data)
    jwt_validate_key = pubkey_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(jwt_validate_key.decode())

    

def find_user(username):
    user = next((u for u in users if u.get("username") == username), None)
    if(user):
        user_index = users.index(user)
        return user_index
    else:
        return -1

def find_kek(file_id):
    key = next((k for k in keys if k.get("file_id") == file_id), None)
    if(key):
        key_index = keys.index(key)
        return key_index
    else:
        return -1

def verify_jwt(headers):
    token = None
    user_index = -1
    try:
        auth_header = headers.get("Authorization", None)
        if(auth_header and auth_header.startswith('Bearer ')):
            token = auth_header.split(" ")[1]
        # else:
        #     token = request.cookies.get("jwt")
    except Exception as e:
        return -1
        
    if(not token):
        print(ALERT_COLOR_BEG + "Missing or invalid Authorization header, verification failed" + COLOR_END)
        return -1
    
    payload = jwt.decode(token, pubkey_key, algorithms=["RS256"])
    user_index = find_user(payload['username'])

    if(user_index != -1):
        print(f"{LOG_COLOR_BEG}Received JWT ({payload['username']}): {token}{COLOR_END}")
        return user_index
    else:
        return -2

def show_users():
    if(len(sys.argv) >= 2 and sys.argv[1] == "test"):
        for user in users:
            print(f"{DB_COLOR_BEG}Username: {user['username']}, Token: {user['token'][:5]}...{COLOR_END}")
    return


def show_keys():
    if(len(sys.argv) >= 2 and sys.argv[1] == "test"):
        for key in keys:
            print(f"{DB_COLOR_BEG}File ID: {key['file_id']}, Owner: {key['owner']}, ACL: {key['acl']}, {COLOR_END}", end="")
            if(key['kek_pubkey']):
                print(f"{DB_COLOR_BEG}KEK Public Key: ..., {COLOR_END}", end="")
            else:
                print(f"{DB_COLOR_BEG}KEK Public Key: None, {COLOR_END}", end="")
            if(key['kek_privkey']):
                print(f"{DB_COLOR_BEG}KEK Private Key: ...{COLOR_END}", end="")
            else:
                print(f"{DB_COLOR_BEG}KEK Private Key: None{COLOR_END}", end="")
            print()
    return


# to-do: receive jwt from server, storing jwt
#        storing generate kek, storing it
#        validate jwt, send kek to user, use kek to decrypt wrapped dek
#        stage 1: refer one kek to one user
#        stage 2: refer multiple kek to one user
#        IP whilelist: file server

# optional: remove outdated jwt
@app.route("/jwt", methods=["POST"])
def handle_jwt():
    data = request.get_json()
    token = data.get("jwt")
    if(not token):
        return jsonify({"status": "error", "message": "No token provided"}), 400

    payload = jwt.decode(token, pubkey_key, algorithms="RS256")
    print(f"{LOG_COLOR_BEG}Received Token: \n{payload['username']}\n{payload['iat']}\n{payload['exp']}{COLOR_END}")
    print(f"{LOG_COLOR_BEG}Received JWT: {token}{COLOR_END}")


    # users.append({"username": payload['username'], "token": token, "kek_privkey": None, "kek_pubkey": None})
    user_index = find_user(payload['username'])
    if(user_index < 0):
        # users.append({"username": payload['username'], "token": token})
        users.append({"username": payload['username'], "token": token})
    else:
        users[user_index]['token'] = token
    return jsonify({"status": "success", "message": f"JWT '{token}' received successfully!"})


@app.route("/kms", methods=["GET", "POST"])
def kms():
    user_index = verify_jwt(request.headers)
    if(user_index == -1):
        return jsonify({"status": "error", "message": "Missing or invalid Authorization header"}), 401
    elif(user_index == -2):
        return jsonify({"status": "error", "message": "Invalid JWT"}), 401
    
    data = request.get_json()
    operation = data.get("operation")

    if(operation == "upload"):
        dek = data.get("dek")
        file_id = data.get("file_id")
        key_index = find_kek(file_id)

        # Generate KEK for the user
        if(key_index < 0):
            keys.append({"file_id": file_id, "owner": users[user_index]['username'], "acl": [], "kek_privkey": None, "kek_pubkey": None})
            key_index = len(keys) - 1

            keys[key_index]['kek_privkey'] = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            keys[key_index]['kek_pubkey'] = keys[key_index]['kek_privkey'].public_key()
        
        # Encrypt Dek using Kek
        dek = base64.b64decode(dek)
        edek = keys[key_index]['kek_pubkey'].encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        edek_base64 = base64.b64encode(edek).decode()
        kek_pubkey_base64 = keys[key_index]['kek_pubkey'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode().replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
        print(f"{KEY_COLOR_BEG}Use KEK ({users[user_index]['username']}): {kek_pubkey_base64}{COLOR_END}")
        print(f"{KEY_COLOR_BEG}Wrapped DEK ({users[user_index]['username']}): {edek_base64}{COLOR_END}")

        show_keys()

        return jsonify({"status": "success", "edek": edek_base64}), 200
    
        
    elif(operation == "download"):
        edek_base64 = data.get("eDek")
        file_id = data.get("file_id")

        if(not edek_base64 or not file_id):
            return jsonify({"status": "error", "message": "No eDek or no file ID provided"}), 400
        
        # Kek access control (policy-based)
        key_index = find_kek(file_id)
        username = users[user_index]['username']
        if(not(keys[key_index]['owner'] == username or username in keys[key_index]['acl'])):
            return jsonify({"status": "error", "message": "invalid user to access kek"})

        # Decrypt Dek using Kek
        edek = base64.b64decode(edek_base64)
        # print(edek)
        dek = keys[key_index]['kek_privkey'].decrypt(
            edek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        dek_base64 = base64.b64encode(dek).decode()
        print(f"{KEY_COLOR_BEG}Unwrapped DEK ({users[user_index]['username']}): {dek_base64}{COLOR_END}")
        return jsonify({"status": "success", "dek": dek_base64}), 200
    
    else:
        return jsonify({"status": "error", "message": "Invalid operation"}), 400

@app.route("/update_acl", methods=["POST"])
def update_acl():
    # to-do: verify file server identity
    data = request.get_json()
    file_id = data.get("file_id")
    username = data.get("username")

    key_index = find_kek(file_id)
    if(key_index < 0):
        return jsonify({"status": "error", "message": "file not found with given file ID."}), 404
    else:
        keys[key_index]['acl'].append(username)

        show_keys()

        return jsonify({"status": "success", "message": f"Update {username} access control of file {file_id}"}), 200




if (__name__ == "__main__"):
    
    context = ('./server/127.0.0.1+2.pem', './server/127.0.0.1+2-key.pem') 
    app.run(host="0.0.0.0", port=8081, ssl_context=context)
    print("KMS Server started on port 8081 with HTTPS")