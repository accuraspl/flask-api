import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app)
#app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:LaFFFFqZTrQOKiBWZEqswlIdzLOYAcHv@switchback.proxy.rlwy.net:17724/railway"
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)

db = SQLAlchemy(app)

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()
from werkzeug.security import check_password_hash
@app.route("/register", methods=["POST"])
def register():
    data = request.json

    if not data.get("email") or not data.get("password"):
        return {"message": "Brak danych"}, 400

    if User.query.filter_by(email=data["email"]).first():
        return {"message": "Użytkownik już istnieje"}, 400

    hashed_password = generate_password_hash(data["password"])

    user = User(
        email=data["email"],
        password=hashed_password
    )

    db.session.add(user)
    db.session.commit()

    return {"message": "Użytkownik utworzony ✅"}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not check_password_hash(user.password, data["password"]):
        return {"message": "Błędne dane logowania"}, 401

    token = create_access_token(identity=str(user.id))
    return {"access_token": token}

@app.route("/profile")
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    return {"message": f"Zalogowany user ID = {user_id}"} 
@app.route("/")

def home():
    try:
        db.engine.connect()
        return jsonify({"status": "Połączono z Railway ✅"})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

@app.route("/debug/users")
def debug_users():
    users = User.query.all()
    return {
        "users": [
            {"id": u.id, "email": u.email, "password": u.password}
            for u in users
        ]
    }