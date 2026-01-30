import os
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_manager, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


with app.app_context():
    db.create_all()


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
           username=username.data).first()
        
        if existing_user_username:
            raise ValidationError(
                "That username already exist, please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Password"})

    submit = SubmitField("Login")


@app.route('/')
def home():
    return render_template('home.html')


@app.route ('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        if bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route ('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
   
    return render_template('register.html', form=form)


if __name__ =='__main__':
    app.run(debug=True)

#lavan's code

import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'statis/bills'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rent_logs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class RentBill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    released = db.Column(db.Boolean, default=True)
    doc_type = db.Column(db.String(20), default='Pdf')
    created_on = db.Column(db.String(20), nullable=False)
    filename = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/logs')
def rent_logs():
    all_bills = RentBill.query.order_by(RentBill.id.desc()).all()
    return render_template('rent_logs.html', bills=all_bills)

@app.route('/upload', methods=['POST'])
def upload_bill():
    if 'file' not in request.files:
        return redirect(url_for('rent_logs'))
    
    file = request.files['file']

    if file.filename == '':
        return redirect(url_for('rent_logs'))
    
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        current_date = datetime.now().strftime("%d/%m/%Y")

        new_bill = RentBill(
            description=filename,
            released=True,
            doc_type='Pdf',
            created_on=current_date,
            filename=filename
        )

    db.session.add(new_bill)
    db.session.commit()
    
    return redirect(url_for('rent_logs'))

if __name__ == '__main__':
    app.run(debug=True)

#Sujiva's code
import os
from flask import Flask, render_template

app = Flask(__name__)

APPS = {
    "plan1": "http://127.0.0.1:5001", 
    "plan2": "http://127.0.0.1:5002", 
    "plan3": "http://127.0.0.1:5003", 
    "plan4": "http://127.0.0.1:5004"  
}

@app.route('/')
def index():
    room_configs = [
        {"img": "room1.jpg", "url": APPS["plan1"]},
        {"img": "room2.jpg", "url": APPS["plan2"]},
        {"img": "room3.jpg", "url": APPS["plan3"]},
        {"img": "room4.jpg", "url": APPS["plan4"]}
    ]
    return render_template('selection.html', rooms=room_configs)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
