import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ------------------ App Configuration ------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'career_ai_secret_2025_super_secure'  # Change in production

# ------------------ Database Setup ------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, 'database')
DB_PATH = os.path.join(DB_DIR, 'users.db')

os.makedirs(DB_DIR, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------ Database Model ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    education = db.Column(db.String(100))
    role = db.Column(db.String(100))

    def __repr__(self):
        return f'<User {self.email}>'

# ------------------ Routes ------------------
@app.route('/')
def home():
    return render_template('index.html')

# ------------------ Register ------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        education = request.form.get('education', '').strip()
        role = request.form.get('role', '').strip()

        if not name or not email or not password:
            flash('Name, Email and Password are required!', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please login.', 'error')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)

        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            education=education,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# ------------------ Login ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Please enter email and password.', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session.clear()  # clear old sessions
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
            session['user_role'] = user.role
            session['user_education'] = user.education

            flash(f'Welcome {user.name}!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'error')

    return render_template('login.html')

# ------------------ Protected Routes ------------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session)

@app.route('/roadmap')
def roadmap():
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    return render_template('roadmap.html', user=user)

@app.route('/practice')
def practice():
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))
    return render_template('practice.html')

@app.route('/mock-interview')
def mock_interview():
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))
    return render_template('mock_interview.html')

@app.route('/progress')
def progress():
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))
    return render_template('progress.html')

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('settings.html', user=user)

# ------------------ Update Profile ------------------
@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    user.name = request.form.get('name', '').strip()
    user.education = request.form.get('education', '').strip()
    user.role = request.form.get('role', '').strip()

    db.session.commit()

    session['user_name'] = user.name
    session['user_role'] = user.role
    session['user_education'] = user.education

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('settings'))

# ------------------ Logout ------------------
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ------------------ Disable Browser Cache (IMPORTANT) ------------------
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ------------------ Run App ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
