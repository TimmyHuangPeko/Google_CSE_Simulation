from flask import Flask, request, jsonify, send_file, redirect, make_response
from pymongo import MongoClient
import requests
import os, sys, datetime
import jwt
from cryptography.hazmat.primitives import serialization
import uuid
import qrcode
import io
import base64
import pyotp

app = Flask(__name__)

UPLOAD_FOLDER = "./temp_storage"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALERT_COLOR_BEG = "\033[91m"
LOG_COLOR_BEG = "\033[90m"
DB_COLOR_BEG = "\033[92m"
COLOR_END = "\033[0m"

# Setup database
users = None
files = None
if(len(sys.argv) >= 2 and sys.argv[1] == "test"):
    users = [
        {"username": "test1", "password": "test1", "totp_secret": None, "token": ""},
        {"username": "test2", "password": "test2", "totp_secret": None, "token": ""}
    ]
    files = []
else:
    # test without docker (without db)
    conn = MongoClient("mongodb://myuser:mysecretpassword@localhost:27017/")

    # print(conn.list_database_names())
    db = conn["mydatabase"]
    users = db["users"]

    users.insert_one({"username": "test1",
                    "password": "test1"})
    
    users.insert_one({"username": "test2",
                      "password": "test2"})
# print(conn.list_database_names())


# Setup JWT signing and validation key pair
privkey_key = None
pubkey_key = None
with open("./server/file_server_prikey.pem", "rb") as f:
    prikey_data = f.read()
    privkey_key = serialization.load_pem_private_key(
        prikey_data,
        password=None,  # or provide the password if your key is encrypted
    )
    jwt_sign_key = privkey_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # or PKCS1 for traditional OpenSSL format
        encryption_algorithm=serialization.NoEncryption()  # or use BestAvailableEncryption(b"password") if you want encryption
    )
    print(jwt_sign_key.decode())

with open("./server/file_server_pubkey.pem", "rb") as f:
    pubkey_data = f.read()
    pubkey_key = serialization.load_pem_public_key(pubkey_data)
    # jwt_validate_key = pubkey_key.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    # print(jwt_validate_key.decode())


# functions
def find_user(username):
    user = next((u for u in users if u.get("username") == username), None)
    if(user):
        user_index = users.index(user)
        return user_index
    else:
        return -1

def find_file(file_id):
    file = next((f for f in files if f.get("file_id") == file_id), None)
    if(file):
        file_index = files.index(file)
        return file_index
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
            print(f"{DB_COLOR_BEG}Username: {user['username']}, Password: {user['password']}{COLOR_END}")
    return
    
def show_files():
    if(len(sys.argv) >= 2 and sys.argv[1] == "test"):
        for file in files:
            print(f"{DB_COLOR_BEG}Filename: {file['filename']}, Owner: {file['owner']}, Valid Users: {file['valid_user']}, Timestamp: {file['timestamp']}{COLOR_END}")
    return

def generate_qr_code(username, totp_secret):
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name='FinalProject')
    qr = qrcode.QRCode()
    qr.add_data(uri)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()


@app.route("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        print(f"{LOG_COLOR_BEG}Received GET request, returning login.html{COLOR_END}")
        return send_file("login.html")

    username = request.form.get("username")
    password = request.form.get("password")
    otp = request.form.get("otp", "")

    print(f"{LOG_COLOR_BEG}Received login request: username = {username}, password = {password}, otp = {otp}{COLOR_END}")

    # Find and authenticate user
    user_index = find_user(username)
    if user_index == -1:
        print(f"{ALERT_COLOR_BEG}Username {username} does not exist, returning error{COLOR_END}")
        return jsonify({"status": "error", "message": "Invalid username"}), 401

    if len(sys.argv) >= 2 and sys.argv[1] == "test":
        user = users[user_index]
        if user['password'] != password:
            print(f"{ALERT_COLOR_BEG}Password error, returning error{COLOR_END}")
            return jsonify({"status": "error", "message": "Password error!"}), 401
    else:
        user = user_index
        if user['password'] != password:
            print(f"{ALERT_COLOR_BEG}Password error, returning error{COLOR_END}")
            return jsonify({"status": "error", "message": "Password error!"}), 401

    # Check or generate TOTP secret
    totp_secret = user.get("totp_secret")
    print(f"{LOG_COLOR_BEG}Checking TOTP secret: totp_secret={totp_secret}{COLOR_END}")

    if not totp_secret:
        print(f"{LOG_COLOR_BEG}TOTP secret does not exist, generating new TOTP secret{COLOR_END}")
        totp_secret = pyotp.random_base32()
        if len(sys.argv) >= 2 and sys.argv[1] == "test":
            users[user_index]["totp_secret"] = totp_secret
        else:
            users.update_one({"username": username}, {"$set": {"totp_secret": totp_secret}})
        qr_code = generate_qr_code(username, totp_secret)
        print(f"{LOG_COLOR_BEG}Generated QR Code{COLOR_END}")
        return jsonify({"status": "qrcode", "qrcode": qr_code, "message": "Please scan this QR Code with Google Authenticator to set up 2FA"})

    # Verify OTP if provided
    totp = pyotp.TOTP(totp_secret)
    if not otp.strip():
        return jsonify({"status": "error", "message": "Please enter the OTP provided by Google Authenticator"}), 401
    if not totp.verify(otp):
        return jsonify({"status": "error", "message": "Invalid OTP, please confirm the code in Google Authenticator is correct"}), 401

    # Generate a JWT token for the user
    # to-do: generate public, private key pair for signing jwt
    payload = {
        "username": users[user_index]["username"],
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    }
    print(f"{LOG_COLOR_BEG}Sent Token: \n{payload['username']}\n{payload['iat']}\n{payload['exp']}{COLOR_END}")
    token = jwt.encode(payload, privkey_key, algorithm="RS256")
    print(f"{LOG_COLOR_BEG}Sent JWT: {token}{COLOR_END}")

    # to-do: cryptographic protection on communication between file server and kms
    kms_response = requests.post(
        "https://localhost:8081/jwt",
        json={"jwt": token if isinstance(token, str) else token.decode()},
        verify=False
    )
    if kms_response.status_code != 200:
        return jsonify({"status": "error", "message": "Failed to send JWT to KMS"}), 500
    
    show_users()

    # If the user exists, return a success response
    return jsonify({"status": "success", "jwt": token, "redirect": "/show"})


@app.route("/show", methods=["GET"])
def show():
    return send_file("upload.html")


@app.route("/ownlist", methods=["GET"])
def ownlist():
    user_index = verify_jwt(request.headers)
    if(user_index < 0):
        return jsonify({"status": "error", "message": "Missing or invalid Authorization header"}), 401
    else:
        username = users[user_index]['username']
        user_files = [f for f in files if f['owner'] == username]
        html = "<h1>Your Files</h1><ul>"
        for f in user_files:
            filename = f['filename'][:-4]
            file_id = f['file_id']
            html += f"""
            <li>
                {filename}
                <button onclick="downloadFile('{filename}', event)" data-field="{file_id}">Download</button>
                <button onclick="deleteFile('{filename}', event)" data-field="{file_id}">Delete</button>
                <button onclick="shareFile('{filename}', event)" data-field="{file_id}">Share</button>
            </li>
            """
        html += "</ul>"
        return html


@app.route("/sharedlist", methods=["GET"])
def sharedlist():
    user_index = verify_jwt(request.headers)
    if(user_index < 0):
        return jsonify({"status": "error", "message": "Missing or invalid Authorization header"}), 401
    else:
        username = users[user_index]['username']
        shared_files = [f for f in files if username in f['valid_user']]
        html = "<h1>Shared Files</h1><ul>"
        for f in shared_files:
            filename = f['filename'][:-4]
            file_id = f['file_id']
            html += f"""
            <li>
                {filename}
                <button onclick="downloadFile('{filename}', event)" data-field="{file_id}">Download</button>
            </li>
            """
        html += "</ul>"
        return html


@app.route("/upload", methods=["GET", "POST"])
def upload():
    user_index = verify_jwt(request.headers)
    if(user_index == -1):
        return jsonify({"status": "error", "message": "Missing or invalid Authorization header"}), 401
    elif(user_index == -2):
        return jsonify({"status": "error", "message": "Invalid JWT"}), 401
    
    # to-do: verify jwt
    if(request.method == "GET"):
        html = f"""
        <h1>Welcome, {users[user_index]['username']}!</h1>
        <h1>Upload File</h1>
        <form id="uploadForm" enctype="multipart/form-data">
            <label for="file">Choose a file:</label>
            <input type="file" name="file" id="uploadFile" required>
            <button type="submit" id="uploadButton">Upload</button>
        </form>
        """
        return html
    
    elif(request.method == "POST"):
        if(request.is_json):
            data = request.get_json()
            filename = data.get("filename")
            file_id = None
            while(1):
                file_id = str(uuid.uuid4())
                if not any(f['file_id'] == file_id for f in files):
                    break
            
            # Save the file to server storage
            # to-do: give each file an unique id
            files.append({"file_id": file_id, "filename": filename + ".enc", "owner": users[user_index]['username'], "valid_user": [], "timestamp": datetime.datetime.now()})
            return jsonify({"status": "success", "file_id": file_id}), 200

        # Check if the request contains a file
        if('file' not in request.files):
            return jsonify({"status": "error", "message": "No file part in the request"}), 400
        
        uploadedfile = request.files['file']

        # Check if a file was selected
        if uploadedfile.filename == '':
            return jsonify({"status": "error", "message": "No file selected"}), 400

        # Entry in files list should already exist, if not, error
        if(not any(f['filename'] == uploadedfile.filename and f['owner'] == users[user_index]['username'] for f in files)):
            # uploaded filename not found
            return jsonify({"status": "error", "message": "File upload failure: filename mismatch"}), 400
        
        # Give file a unique id (random-based UUID v4, refer to RFC 4122)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], users[user_index]['username'])
        if not os.path.exists(file_path):
            os.makedirs(file_path)
        uploadedfile.save(os.path.join(app.config['UPLOAD_FOLDER'], users[user_index]['username'], uploadedfile.filename))
        
        show_files()
        return jsonify({"status": "success", "message": f"File '{uploadedfile.filename[:-4]}' uploaded successfully!"})


@app.route("/download", methods=["GET"])
def download():
    user_index = verify_jwt(request.headers)
    if(user_index == -1):
        return jsonify({"status": "error", "message": "Missing or invalid Authorization header"}), 401
    elif(user_index == -2):
        return jsonify({"status": "error", "message": "Invalid JWT"}), 401
    
    # filename = request.args.get("filename") + ".enc"
    # ownername = request.args.get("username")
    file_id = request.args.get("file_id")

    # Check ownership
    if (not any(f['file_id'] == file_id and (f['owner'] == users[user_index]['username'] or users[user_index]['username'] in f['valid_user']) for f in files)):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    
    file_index = find_file(file_id)
    filename = files[file_index]['filename']
    ownername = files[file_index]['owner']

    file_path = os.path.join("../", app.config['UPLOAD_FOLDER'], ownername, filename)
    return send_file(file_path, as_attachment=True)


@app.route("/share", methods=["POST"])
def share():
    user_index = verify_jwt(request.headers)
    if(user_index == -1):
        return jsonify({"status": "error", "message": "Missing or invalid Authorization header"}), 401
    elif(user_index == -2):
        return jsonify({"status": "error", "message": "Invalid JWT"}), 401
    
    data = request.get_json()
    file_id = data.get("file_id")
    share_with = data.get("share_with")
    file_index = find_file(file_id)
    filename = files[file_index]['filename']

    # Check ownership
    if not any(f['file_id'] == file_id and f['owner'] == users[user_index]['username'] for f in files):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    # Add the user to the valid_user list
    for f in files:
        if f['file_id'] == file_id:
            if share_with not in f['valid_user']:
                f['valid_user'].append(share_with)
            break

    # Told KMS to update KEK access control list
    kms_response = requests.post(
        "https://localhost:8081/update_acl",
        json={"file_id": file_id, "username": share_with},
        verify=False
    )
    if(kms_response.status_code != 200):
        return jsonify({"status": "error", "message": "Failed to update ACL"}), 500
    
    return jsonify({"status": "success", "message": f"File '{filename[:-4]}' shared with {share_with}!"})

if (__name__ == "__main__"):
    context = ('./server/127.0.0.1+2.pem', './server/127.0.0.1+2-key.pem') 
    app.run(host="0.0.0.0", port=8080, ssl_context=context)
    print("Server started on port 8080 with HTTPS")


# add directory
# expired jwt
# encrypt get argument?