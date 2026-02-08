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


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static/bills')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


ROOM_DATA = {
    "room1": {
        "id": "room1", 
        "name": "House Layout 1", 
        "img": "room1.jpg", 
        "e_rate": 0.50, "w_rate": 1.00, 
        "desc": "2 rooms divided equally.",
        "sub_rooms": [
            {"id": "r1_a", "name": "Room A (Standard)", "rent": 450},
            {"id": "r1_b", "name": "Room B (Standard)", "rent": 450}
        ]
    },
    "room2": {
        "id": "room2", 
        "name": "House Layout 2", 
        "img": "room2.jpg", 
        "e_rate": 0.33, "w_rate": 0.66, 
        "desc": "3 rooms divided equally.",
        "sub_rooms": [
            {"id": "r2_a", "name": "Room A", "rent": 320},
            {"id": "r2_b", "name": "Room B", "rent": 320},
            {"id": "r2_c", "name": "Room C", "rent": 320}
        ]
    },
    "room3": {
        "id": "room3", 
        "name": "House Layout 3", 
        "img": "room3.jpg", 
        "e_rate": 0.76, "w_rate": 1.33, 
        "desc": "A single large room.",
        "sub_rooms": [
            {"id": "r3_a", "name": "Master Suite", "rent": 720}
        ]
    },
    "room4": {
        "id": "room4", 
        "name": "House Layout 4", 
        "img": "room4.jpg", 
        "e_rate": 1.00, "w_rate": 2.00, 
        "desc": "2 rooms with one being larger and the other being smaller.",
        "sub_rooms": [
            {"id": "r4_large", "name": "Master Bedroom (Large)", "rent": 510},
            {"id": "r4_small", "name": "Compact Room (Small)", "rent": 320}
        ]
    }
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    selected_layout_id = db.Column(db.String(20), nullable=True)
    selected_sub_room_id = db.Column(db.String(20), nullable=True)

class RentBill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    released = db.Column(db.Boolean, default=True)
    doc_type = db.Column(db.String(20), default='Pdf')
    created_on = db.Column(db.String(20), nullable=False)
    filename = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing = User.query.filter_by(username=username.data).first()
        if existing: raise ValidationError("That username already exists.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")


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


@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.selected_layout_id:
        return redirect(url_for('select_layout'))
    
    layout = ROOM_DATA.get(current_user.selected_layout_id)
    
    sub_room_name = "Unknown Room"
    sub_room_rent = 0
    if layout and current_user.selected_sub_room_id:
        for r in layout['sub_rooms']:
            if r['id'] == current_user.selected_sub_room_id:
                sub_room_name = r['name']
                sub_room_rent = r.get('rent', 0)
                break

    all_bills = RentBill.query.order_by(RentBill.id.desc()).all()
    
    return render_template('dashboard.html', 
                           mode='dashboard',
                           bills=all_bills, 
                           layout=layout,
                           sub_room_name=sub_room_name,
                            sub_room_rent=sub_room_rent)


@app.route('/select/layout')
@login_required
def select_layout():
    if current_user.selected_layout_id: return redirect(url_for('dashboard'))
    return render_template('dashboard.html', mode='step_1_layout', rooms=ROOM_DATA)

@app.route('/select/layout/<layout_id>')
@login_required
def select_sub_room(layout_id):
    if current_user.selected_layout_id: return redirect(url_for('dashboard'))
    
    layout = ROOM_DATA.get(layout_id)
    if not layout: return redirect(url_for('select_layout'))
    
    return render_template('dashboard.html', mode='step_2_subroom', layout=layout)

@app.route('/select/confirm/<layout_id>/<sub_room_id>')
@login_required
def confirm_selection(layout_id, sub_room_id):
    if current_user.selected_layout_id: return redirect(url_for('dashboard'))
    
    layout = ROOM_DATA.get(layout_id)
    target_room = next((r for r in layout['sub_rooms'] if r['id'] == sub_room_id), None)
    
    if not layout or not target_room: return redirect(url_for('select_layout'))

    return render_template('dashboard.html', mode='step_3_confirm', layout=layout, sub_room=target_room)

@app.route('/select/finalize/<layout_id>/<sub_room_id>', methods=['POST'])
@login_required
def finalize_selection(layout_id, sub_room_id):
    if current_user.selected_layout_id: return redirect(url_for('dashboard'))
    
    if layout_id in ROOM_DATA:
        current_user.selected_layout_id = layout_id
        current_user.selected_sub_room_id = sub_room_id
        db.session.commit()
        
    return redirect(url_for('dashboard'))


@app.route('/upload', methods=['POST'])
@login_required
def upload_bill():
    if 'file' not in request.files: return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '': return redirect(url_for('dashboard'))
    
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