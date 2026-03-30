import warnings
warnings.filterwarnings("ignore")
import os

from google import genai

client = genai.Client(api_key="AIzaSyDvi6KAmwSW-u6Ar5CRlfe3tXRW-OmYAcg")

TEMP_FOLDER = "temp"
os.makedirs(TEMP_FOLDER, exist_ok=True)

from flask import Flask, render_template, request, redirect, session, send_file, jsonify
import os, time, pyotp, sqlite3, io, hashlib

from encryption import encrypt_file, decrypt_file
from otp_utils import generate_otp, verify_otp
from email_utils import send_email_otp
from sms_utils import send_sms_otp

app = Flask(__name__)
app.secret_key = "ghostkey_secure"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- MEMORY STORAGE ----------------

login_attempts = {}
secure_links = {}
account_locked = {}
security_logs = []
intrusion_logs = []

pending_encrypt = {}
pending_decrypt = {}

# ---------------- LOG FUNCTIONS ----------------

def add_log(user, action):
    security_logs.append({"user": user, "action": action})

def add_intrusion(user, alert):
    intrusion_logs.append({"user": user, "alert": alert})

# ---------------- DATABASE ----------------

def init_db():

    conn = sqlite3.connect("ghostkey.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        email TEXT PRIMARY KEY,
        password TEXT,
        phone TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS file_keys(
        user TEXT,
        filename TEXT,
        encryption_key TEXT,
        file_hash TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ---------------- HOME ----------------

@app.route("/")
def index():
    return render_template("index.html")

# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]
        phone = request.form["phone"]

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect("ghostkey.db")
        c = conn.cursor()

        try:
            c.execute(
                "INSERT INTO users VALUES (?, ?, ?)",
                (email, password_hash, phone)
            )
            conn.commit()
        except:
            conn.close()
            return "User already exists"

        conn.close()

        add_log(email,"User registered")

        return redirect("/login")

    return render_template("register.html")

# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect("ghostkey.db")
        c = conn.cursor()

        c.execute("SELECT password, phone FROM users WHERE email=?", (email,))
        result = c.fetchone()

        conn.close()

        if result and result[0] == password_hash:

            phone = result[1]

            secret = pyotp.random_base32()
            otp = generate_otp(secret)

            session["email"] = email
            session["otp_secret"] = secret

            send_email_otp(email, otp)
            send_sms_otp(phone, otp)

            print("LOGIN OTP:", otp)

            add_log(email,"Login OTP sent")

            return render_template("otp.html")

        else:
            add_intrusion(email,"Invalid login attempt")
            return "Invalid email or password"

    return render_template("login.html")

# ---------------- VERIFY OTP ----------------

@app.route("/verify", methods=["POST"])
def verify():

    otp = request.form["otp"]
    user = session.get("email")

    if not user:
        add_intrusion("Unknown","Unauthorized access")
        return redirect("/login")
    
    # 🔥 CHECK LOCK
    if user in account_locked:
        if time.time() < account_locked[user]:
            return "⚠️ Account locked. Try again later"
        else:
            del account_locked[user]
            login_attempts[user] = 0

    if verify_otp(session["otp_secret"], otp):

        login_attempts[user] = 0
        add_log(user,"Login success")

        return redirect("/dashboard")

    else:

        login_attempts[user] = login_attempts.get(user,0)+1
        
        add_intrusion(user,"Invalid OTP attempt")


    if login_attempts[user] >= 3:
        
        add_intrusion(user,"Multiple OTP failures")
        account_locked[user] = time.time() + 120   # lock 2 min
        add_intrusion(user,"Account temporarily locked")
        return "Invalid OTP"

# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if "email" not in session:
        add_intrusion("Unknown","Unauthorized dashboard access")
        return redirect("/login")

    conn = sqlite3.connect("ghostkey.db")
    c = conn.cursor()

    c.execute(
        "SELECT filename FROM file_keys WHERE user=?",
        (session["email"],)
    )

    files = [row[0] for row in c.fetchall()]

    conn.close()
    return render_template("dashboard.html", files=files, intrusions=intrusion_logs)
# ---------------- ENCRYPT FILE ----------------

@app.route("/encrypt", methods=["GET","POST"])
def encrypt_page():

    if "email" not in session:
        return redirect("/login")

    if request.method == "POST":

        file = request.files["file"]
        password = request.form["password"]

        if file.filename == "":
            return "No file selected"

        filename = file.filename
        data = file.read()

        # -------- Generate OTP --------
        secret = pyotp.random_base32()
        otp = generate_otp(secret)

        session["otp_secret"] = secret
        session["resend_count"] = 0   # reset resend

        # -------- GET USER PHONE --------
        conn = sqlite3.connect("ghostkey.db")
        c = conn.cursor()
        c.execute("SELECT phone FROM users WHERE email=?", (session["email"],))
        result = c.fetchone()
        conn.close()

        if not result:
            return "User phone not found"

        phone = result[0]

        # -------- SEND OTP TO BOTH --------
        send_email_otp(session["email"], otp)
        send_sms_otp(phone, otp)

        print("ENCRYPT OTP (EMAIL + SMS):", otp)

        # -------- STORE TEMP DATA --------
        pending_encrypt[session["email"]] = {
            "filename": filename,
            "data": data,
            "password": password
        }

        return render_template("verify_encrypt_otp.html")

    return render_template("encrypt.html")




    # -------- VERIFY ENCRYPT --------



@app.route("/verify_encrypt", methods=["POST"])
def verify_encrypt():

    if "email" not in session:
        return redirect("/login")

    email_otp = request.form["email_otp"]
    sms_otp = request.form["sms_otp"]

    # -------- VERIFY BOTH OTP --------
    if not verify_otp(session["otp_secret"], email_otp):
        add_intrusion(session["email"],"Wrong Email OTP (Encryption)")
        return "Invalid Email OTP"

    if not verify_otp(session["otp_secret"], sms_otp):
        add_intrusion(session["email"],"Wrong SMS OTP (Decryption)")
        return "Invalid SMS OTP"

    action = pending_encrypt.get(session["email"])

    if not action:
        return "Encryption session expired"

    filename = action["filename"]
    data = action["data"]
    password = action["password"]

    key = hashlib.sha256(password.encode()).digest()
    encrypted_data = encrypt_file(data, key)

    encrypted_filename = filename + ".enc"
    encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)

    with open(encrypted_path,"wb") as f:
        f.write(encrypted_data)

    file_hash = hashlib.sha256(data).hexdigest()

    conn = sqlite3.connect("ghostkey.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO file_keys VALUES (?, ?, ?, ?)",
        (session["email"], encrypted_filename, key.hex(), file_hash)
    )

    conn.commit()
    conn.close()

    del pending_encrypt[session["email"]]

    return redirect("/dashboard")



# ---------------- DOWNLOAD REQUEST ----------------

@app.route("/download_request/<filename>")
def download_request(filename):

    if "email" not in session:
        return redirect("/login")

    filepath = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(filepath):
        return "File not found"

    conn = sqlite3.connect("ghostkey.db")
    c = conn.cursor()

    c.execute(
    "SELECT encryption_key FROM file_keys WHERE filename=? AND user=?",
    (filename, session["email"])
    )

    result = c.fetchone()
    conn.close()

    if not result:
        return "Encryption key not found"

    key = bytes.fromhex(result[0])

    with open(filepath,"rb") as f:
        encrypted = f.read()

    try:
        decrypted = decrypt_file(encrypted,key)
        # -------- INTEGRITY CHECK --------

        current_hash = hashlib.sha256(decrypted).hexdigest()

        conn = sqlite3.connect("ghostkey.db")
        c = conn.cursor()

        c.execute(
            "SELECT file_hash FROM file_keys WHERE filename=?",
            (filename,)
        )

        result = c.fetchone()
        conn.close()

        stored_hash = result[0]

        if current_hash != stored_hash:
            add_intrusion(session["email"], "File tampering detected")
            return "⚠️ File integrity check failed! File may be modified."

        else:
            print("Integrity Verified ✅")
    except:
        add_intrusion(session["email"],"Decryption failed")
        return "Decryption failed"

    add_log(session["email"], f"File downloaded: {filename}")

    return send_file(
        io.BytesIO(decrypted),
        download_name=filename.replace(".enc",""),
        as_attachment=True
    )

# ---------------- GENERATE SHARE LINK ----------------

@app.route("/generate_link/<filename>")
def generate_link(filename):

    if "email" not in session:
        return redirect("/login")

    filepath = os.path.join(UPLOAD_FOLDER, filename)

    conn = sqlite3.connect("ghostkey.db")
    c = conn.cursor()

    c.execute(
            "SELECT filename FROM file_keys WHERE filename=? AND user=?",
            (filename, session["email"])
        )

    result = c.fetchone()
    conn.close()

    if not result:
            return "❌ Unauthorized: You can only share your own files"

    token = str(time.time())
    expiry = time.time() + 120

    secure_links[token] = {
    "file": filename,
    "expiry": expiry,
    "used": False,
    "owner": session["email"]
    
    }

    link = f"http://127.0.0.1:5000/secure_download/{token}"

    add_log(session["email"], f"Share link generated for {filename}")

    return render_template("share_link.html", link=link)

# ---------------- SECURE DOWNLOAD ----------------

@app.route("/secure_download/<token>")
def secure_download(token):

    if token not in secure_links:
        return "Invalid or expired link"

    data = secure_links[token]
    if data["used"]:
        return "Link already used"

    data["used"] = True

    if "email" not in session:
            return "Please login to access this file"

    if session["email"] not in [data["owner"], data.get("shared_user")]:
        return "❌ Unauthorized access"


    if time.time() > data["expiry"]:
        return "Download link expired"

    filename = data["file"]
    path = os.path.join(UPLOAD_FOLDER, filename)

    with open(path,"rb") as f:
        encrypted = f.read()

    add_log("external_user", f"Secure link download: {filename}")

    return send_file(
        io.BytesIO(encrypted),
        download_name=filename,
        as_attachment=True
    )
# -------- DELETE --------

@app.route("/delete_file/<filename>")
def delete_file(filename):

    if "email" not in session:
        return redirect("/login")

    # -------- CHECK OWNERSHIP --------
    conn = sqlite3.connect("ghostkey.db")
    c = conn.cursor()

    c.execute(
        "SELECT filename FROM file_keys WHERE filename=? AND user=?",
        (filename, session["email"])
    )

    result = c.fetchone()

    if not result:
        conn.close()
        return "❌ Unauthorized: You cannot delete this file"

    # -------- DELETE FROM FOLDER --------
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if os.path.exists(file_path):
        os.remove(file_path)

    # -------- DELETE FROM DATABASE --------
    c.execute(
        "DELETE FROM file_keys WHERE filename=? AND user=?",
        (filename, session["email"])
    )

    conn.commit()
    conn.close()

    add_log(session["email"], f"File deleted: {filename}")

    return redirect("/dashboard")


# ---------------- DECRYPT ----------------
@app.route("/decrypt", methods=["GET","POST"])
def decrypt_page():

    if "email" not in session:
        return redirect("/login")

    if request.method == "POST":

        file = request.files["file"]
        password = request.form["password"]

        if file.filename == "":
            return "No file selected"

        filename = file.filename
        data = file.read()

        # -------- GENERATE OTP --------
        secret = pyotp.random_base32()
        otp = generate_otp(secret)

        session["otp_secret"] = secret
        session["resend_count"] = 0

        # -------- GET USER PHONE --------
        conn = sqlite3.connect("ghostkey.db")
        c = conn.cursor()
        c.execute("SELECT phone FROM users WHERE email=?", (session["email"],))
        result = c.fetchone()
        conn.close()

        if not result:
            return "User phone not found"

        phone = result[0]

        # -------- SEND OTP TO BOTH --------
        send_email_otp(session["email"], otp)
        send_sms_otp(phone, otp)

        print("DECRYPT OTP (EMAIL + SMS):", otp)

        # -------- STORE TEMP DATA --------
        pending_decrypt[session["email"]] = {
            "filename": filename,
            "data": data,
            "password": password
        }

        return render_template("verify_decrypt_otp.html")

    return render_template("decrypt.html")



@app.route("/verify_decrypt", methods=["POST"])
def verify_decrypt():

    if "email" not in session:
        return redirect("/login")

    email_otp = request.form["email_otp"]
    sms_otp = request.form["sms_otp"]

    # -------- VERIFY BOTH OTP --------
    if not verify_otp(session["otp_secret"], email_otp):
        add_intrusion(session["email"],"Wrong Email OTP (Decryption)")
        return "Invalid Email OTP"

    if not verify_otp(session["otp_secret"], sms_otp):
        add_intrusion(session["email"],"Wrong SMS OTP (Decryption)")
        return "Invalid SMS OTP"

    action = pending_decrypt.get(session["email"])

    if not action:
        return "Decryption session expired"

    filename = action["filename"]
    data = action["data"]
    password = action["password"]

    # -------- DECRYPT --------
    key = hashlib.sha256(password.encode()).digest()

    try:
        decrypted_data = decrypt_file(data, key)
        # -------- STORE TEMP FILE --------
        temp_filename = "decrypted_" + filename.replace(".enc", "")
        temp_path = os.path.join(TEMP_FOLDER, temp_filename)

        with open(temp_path, "wb") as f:
            f.write(decrypted_data)

        session["temp_file_path"] = temp_path
        session["download_filename"] = temp_filename
        session["download_filename"] = filename.replace(".enc", "")
       
# -------- INTEGRITY CHECK --------

        current_hash = hashlib.sha256(decrypted_data).hexdigest()

        conn = sqlite3.connect("ghostkey.db")
        c = conn.cursor()

        c.execute(
            "SELECT file_hash FROM file_keys WHERE filename=?",
            (filename,)
        )

        result = c.fetchone()
        conn.close()

        stored_hash = result[0]

        # -------- SEND RESULT TO UI --------

        if current_hash != stored_hash:
            status = "tampered"
        else:
            status = "safe"

        return render_template(
    "verify_decrypt_otp.html",
    integrity_status=status,
    allow_download=(status == "safe")
        )
    except:
        add_intrusion(session["email"],"Decryption failed")
        return "Decryption failed (wrong password or corrupted file)"

    # -------- RETURN FILE --------
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=filename.replace(".enc", ""),
        as_attachment=True
    )

@app.route("/download_decrypted")
def download_decrypted():

    if "temp_file_path" not in session:
        return "No file available"

    path = session["temp_file_path"]
    filename = session.get("download_filename", "file")

    # send file
    response = send_file(
        path,
        as_attachment=True,
        download_name=filename
    )

    # delete after sending
    try:
        os.remove(path)
    except:
        pass

    return response
# ---------------- SHARE ----------------

@app.route("/share", methods=["GET","POST"])
def share_page():

    if "email" not in session:
        return redirect("/login")

    link=None

    if request.method=="POST":

        file=request.files["file"]

        if file.filename == "":
            return "No file selected"

        filename=file.filename
        path=os.path.join(UPLOAD_FOLDER, filename)

        file.save(path)

        token=str(time.time())
        expiry=time.time()+120

        secure_links[token]={
            "file":filename,
            "expiry":expiry
        }

        link=f"http://127.0.0.1:5000/secure_download/{token}"

        add_log(session["email"],f"File shared: {filename}")

    return render_template("share.html",link=link)
# ---------------- SECURITY DASHBOARD ----------------

@app.route("/security_dashboard")
def security_dashboard():

    if "email" not in session:
        add_intrusion(session["email"],"Decryption failed")
        return redirect("/login")

    return render_template(
        "security_dashboard.html",
        logs=security_logs,
        intrusions=intrusion_logs
    )

# ---------------- CHATBOT ----------------

@app.route("/ask", methods=["POST"])
def ask():

    user_input = request.form.get("message")

    try:
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=user_input
        )

        return jsonify({"response": response.text})

    except Exception as e:
        print(e)
        return jsonify({"response": "AI error"})


@app.route("/chatbot")
def chatbot():
    return render_template("chatbot.html")

# ---------------- RESEND OTP ----------------

@app.route('/resend-otp', methods=['POST'])
def resend_otp():

    if "email" not in session or "otp_secret" not in session:
        return jsonify({"message": "Session expired"}), 401

    email = session["email"]
    secret = session["otp_secret"]

    # -------- LIMIT RESEND --------
    if "resend_count" not in session:
        session["resend_count"] = 0

    if session["resend_count"] >= 3:
        return jsonify({"message": "Resend limit reached"}), 403

    session["resend_count"] += 1

    # -------- GENERATE OTP CORRECTLY --------
    otp = generate_otp(secret)

    print("RESEND OTP:", otp)   # 👈 VERY IMPORTANT (debug)

    # -------- SEND EMAIL --------
    send_email_otp(email, otp)

    return jsonify({"message": "OTP resent successfully"})
# ---------------- LOGOUT ----------------


@app.route("/logout")
def logout():

    user = session.get("email","unknown")

    add_log(user,"User logged out")

    session.clear()

    return redirect("/login")

# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(debug=True)