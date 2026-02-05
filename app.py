import os
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_manager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static/bills') # Fix path to be absolute or relative correctly
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --- ROOM DATA CONFIGURATION ---
ROOM_DATA = {
    "room1": {"id": "room1", "name": "Room 1", "img": "room1.jpg", "e_rate": 0.50, "w_rate": 1.00, "desc": "Standard single room layout."},
    "room2": {"id": "room2", "name": "Room 2", "img": "room2.jpg", "e_rate": 0.33, "w_rate": 0.66, "desc": "Compact room with efficient rates."},
    "room3": {"id": "room3", "name": "Room 3", "img": "room3.jpg", "e_rate": 0.76, "w_rate": 1.33, "desc": "Spacious room with premium amenities."},
    "room4": {"id": "room4", "name": "Room 4", "img": "room4.jpg", "e_rate": 1.00, "w_rate": 2.00, "desc": "Deluxe master suite layout."}
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- UPDATED DATABASE MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    # New column to store the user's room choice
    selected_room = db.Column(db.String(20), nullable=True)

class RentBill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    released = db.Column(db.Boolean, default=True)
    doc_type = db.Column(db.String(20), default='Pdf')
    created_on = db.Column(db.String(20), nullable=False)
    filename = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

# --- FORMS ---
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exist, please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# --- DASHBOARD & LOGIC ROUTES ---

@app.route('/select_room/<room_id>', methods=['POST'])
@login_required
def select_room_action(room_id):
    """Route to handle the room selection submission."""
    if room_id in ROOM_DATA:
        current_user.selected_room = room_id
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # MODE 1: Room Selection
    # If the user has NOT selected a room yet, show the selection view
    if not current_user.selected_room:
        return render_template('dashboard.html', mode='selection', rooms=ROOM_DATA)

    # MODE 2: Normal Dashboard (Calculator + Logs)
    # If the user HAS selected a room, show the dashboard
    
    room_info = ROOM_DATA.get(current_user.selected_room)
    
    # Calculator Logic
    e_usage = 0.0
    w_usage = 0.0
    total_price = 0.0
    
    if request.method == 'POST' and 'e_usage' in request.form:
        try:
            e_usage = float(request.form.get('e_usage', 0) or 0)
            w_usage = float(request.form.get('w_usage', 0) or 0)
            total_price = (e_usage * room_info['e_rate']) + (w_usage * room_info['w_rate'])
        except ValueError:
            pass

    # Fetch Rent Logs
    all_bills = RentBill.query.order_by(RentBill.id.desc()).all()
    
    return render_template('dashboard.html', 
                           mode='dashboard',
                           bills=all_bills, 
                           room=room_info,
                           e_usage=e_usage, 
                           w_usage=w_usage, 
                           total_price=total_price)

@app.route('/upload', methods=['POST'])
@login_required
def upload_bill():
    if 'file' not in request.files:
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('dashboard'))
    
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        current_date = datetime.now().strftime("%d/%m/%Y")
        new_bill = RentBill(
            description=filename, released=True, doc_type='Pdf',
            created_on=current_date, filename=filename
        )
        db.session.add(new_bill)
        db.session.commit()
    
    return redirect(url_for('dashboard'))

if __name__ =='__main__':
    app.run(debug=True)