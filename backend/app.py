import os
import datetime
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
import mysql.connector
import bcrypt
import jwt

load_dotenv()

app = Flask(__name__)
CORS(app)

# Config
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
JWT_SECRET = os.getenv("JWT_SECRET")

def get_db():
    return mysql.connector.connect(
        host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS
    )

@app.route("/")
def health():
    return {"status": "running"}

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return {"message": "Username and password required"}, 400
    
    username, password = data["username"], data["password"]
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = %s", 
                      (username,))
        row = cursor.fetchone()
        
        if not row or not bcrypt.checkpw(password.encode(), row[2].encode()):
            return {"message": "Invalid credentials"}, 401
        
        token = jwt.encode({
            "sub": str(row[0]),
            "username": row[1],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, JWT_SECRET, algorithm="HS256")
        
        return {"token": token}
    finally:
        cursor.close()
        conn.close()

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return {"message": "Username and password required"}, 400
    
    username, password = data["username"], data["password"]
    pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", 
                      (username, pwd_hash))
        conn.commit()
        return {"message": "User created"}, 201
    except Exception as e:
        return {"message": "Error creating user", "error": str(e)}, 400
    finally:
        cursor.close()
        conn.close()





def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"message": "Token missing"}), 401
        token = auth.split(" ")[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            g.user = {"id": payload["sub"], "username": payload["username"]}
        except:
            return jsonify({"message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/users", methods=["GET"])
@token_required
def get_users():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM users")
        users = [{"id": row[0], "username": row[1]} for row in cursor.fetchall()]
        return users
    finally:
        cursor.close()
        conn.close()

@app.route("/users/<int:user_id>", methods=["DELETE"])
@token_required
def delete_user(user_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        return {"message": "User deleted"}
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("DEBUG", "False").lower() in ["true", "1", "yes"]
    app.run(host="0.0.0.0", port=port, debug=debug)
