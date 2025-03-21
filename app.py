from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users1.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(message)s')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    login_start = db.Column(db.String(5), nullable=False)
    login_end = db.Column(db.String(5), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html', user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    username_error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        login_start = request.form['login_start']
        login_end = request.form['login_end']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter_by(username=username).first():
            username_error = "⚠️ Username already taken. Try another."
            return render_template('register.html', username_error=username_error)

        new_user = User(username=username, password=hashed_password, login_start=login_start, login_end=login_end)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    username_error = None
    password_error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if not user:
            username_error = "⚠️ Username does not exist."
            return render_template('login.html', username_error=username_error)

        if not check_password_hash(user.password, password):
            password_error = "⚠️ Incorrect password."
            return render_template('login.html', password_error=password_error)

        current_time = datetime.now().strftime("%H:%M")
        if not (user.login_start <= current_time <= user.login_end):
            flash(f"⏳ You can only login between {user.login_start} and {user.login_end}.", "warning")
            return redirect(url_for('login'))

        login_user(user)
        flash("✅ Login successful!", "success")
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("🔒 You have been logged out.", "info")
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)