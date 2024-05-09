from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_user, login_required, logout_user
from sqlalchemy import text
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, redirect, url_for, flash
from project.models import User, db

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form['email']
    password = request.form['password']
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password and compare it with the stored password
    if user and check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        current_app.logger.warning("User login failed")
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form['email']
    password = request.form['password'] 
    hashed_password = generate_password_hash(password, method='sha256')
# Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email address already in use.')
        return redirect(url_for('auth.signup'))
# Create new user instance
    new_user = User(email=email, password=hashed_password)  # Assume password hashing is handled in the User model 
    # Add new user to the database
    db.session.add(new_user)
    db.session.commit()

    flash('Registration successful!')
    return redirect(url_for('main.profile')) 

@auth.route('/logout')
@login_required
def logout():
    logout_user();
    return redirect(url_for('main.index'))

# See https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login for more information
