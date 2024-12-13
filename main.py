from flask import Flask, request, jsonify
import jwt
import datetime
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Секретний ключ для підпису JWT
SECRET_KEY = "your_secret_key"

# Простий "фіктивний" список користувачів
users = {
    "testuser": generate_password_hash("password123")
}

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password required"}), 400

    username = data['username']
    password = data['password']

    # Перевірка користувача
    user_password_hash = users.get(username)
    if not user_password_hash or not check_password_hash(user_password_hash, password):
        return jsonify({"message": "Invalid username or password"}), 401

    # Генеруємо токен
    token = jwt.encode({
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token})

@app.route('/protected', methods=['GET'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"message": "Token is missing or invalid"}), 401

    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"message": f"Welcome {payload['username']}! This is a protected resource."})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(debug=True)

