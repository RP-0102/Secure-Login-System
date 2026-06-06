import os
from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False) 

with app.app_context():
    db.create_all()

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Secure Login System</title></head>
<body style="font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px;">
    <h2>🔐 Secure Account Access</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}{% for msg in messages %}<p style="color: red;">{{ msg }}</p>{% endfor %}{% endif %}
    {% endwith %}
    <form method="POST" action="/login">
        <label>Username:</label><br>
        <input type="text" name="username" required style="width:100%; margin-bottom:15px; padding:8px;"><br>
        <label>Password:</label><br>
        <input type="password" name="password" required style="width:100%; margin-bottom:15px; padding:8px;"><br>
        <button type="submit" style="width:100%; padding:10px; background:#28a745; color:white; border:none; border-radius:4px; cursor:pointer;">Login</button>
    </form>
    <p style="margin-top:15px; text-align:center;">New here? <a href="/register">Register account</a></p>
</body>
</html>
"""

REGISTER_HTML = """
<!DOCTYPE html>
<html>
<head><title>Create Secure Account</title></head>
<body style="font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px;">
    <h2>👤 User Registration</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}{% for msg in messages %}<p style="color: red;">{{ msg }}</p>{% endfor %}{% endif %}
    {% endwith %}
    <form method="POST" action="/register">
        <label>Username:</label><br>
        <input type="text" name="username" required style="width:100%; margin-bottom:15px; padding:8px;"><br>
        <label>Email Address:</label><br>
        <input type="email" name="email" required style="width:100%; margin-bottom:15px; padding:8px;"><br>
        <label>Password:</label><br>
        <input type="password" name="password" required style="width:100%; margin-bottom:15px; padding:8px;"><br>
        <button type="submit" style="width:100%; padding:10px; background:#007bff; color:white; border:none; border-radius:4px; cursor:pointer;">Create Account</button>
    </form>
    <p style="margin-top:15px; text-align:center;">Existing user? <a href="/login">Login here</a></p>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; text-align: center;">
    <h1 style="color: #28a745;">✅ Welcome to the Vault, {{ username }}!</h1>
    <p>Authentication State Status: <strong>VALID ACTIVE SESSION</strong></p>
    <p>Your plain-text password is safe; it exists inside our database only as a 60-character salted blowfish hash string.</p>
    <br><br>
    <a href="/logout" style="padding:10px 20px; background:#dc3545; color:white; text-decoration:none; border-radius:4px;">Securely Sign Out</a>
</body>
</html>
"""

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form['username'].strip()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid authentication credentials.")
            return redirect(url_for('login'))

    return render_template_string(LOGIN_HTML)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if len(password) < 8:
            flash("Registration failed: Password must contain at least 8 characters.")
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Registration failed: Username or email is already registered.")
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully. Please login below!")
        return redirect(url_for('login'))

    return render_template_string(REGISTER_HTML)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Unauthorized Access: Active authenticated session token missing.")
        return redirect(url_for('login'))
    return render_template_string(DASHBOARD_HTML, username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)