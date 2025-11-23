import os
from flask import Flask, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)


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
        


@app.route('/')
def home():
    return render_template('home.html')


@app.route ('/login')
def login():
    return render_template('login.html')

@app.route ('/register')
def register():
    return render_template('register.html')


if __name__ =='__main__':
    app.run(debug=True)