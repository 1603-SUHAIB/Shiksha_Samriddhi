from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from pymongo import MongoClient
from Crypto.Cipher import AES
import base64
import random
import smtplib
import os
import bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(24)

try:
    client = MongoClient('mongodb://localhost:27017/')
    db = client['institution_portal']
    users = db['users']
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

AES_KEY = b'vV5KznJbWxR8rSC4'


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))


def encrypt_password(password):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
        return base64.b64encode(nonce + ciphertext).decode('utf-8')
    except Exception as e:
        print(f"Error encrypting password: {e}")


def send_email(to_email, otp):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login('forprojectuseemail@gmail.com', 'dykt kvbb gwzl llhw')  # Use your email and app password
        message = f"Subject: OTP Verification\n\nYour OTP is: {otp}"
        server.sendmail('forprojectuseemail@gmail.com', to_email, message)
        server.quit()
    except Exception as e:
        print(f"Error sending email: {e}")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print("Received POST request")

        # Extract form data
        udise_code = request.form.get('username')
        password = request.form.get('password')

        # Fetch user from the database using the correct field name
        user = users.find_one({'udiseCode': udise_code})
        print("Fetched user:", user)

        if user:
            # Check if the provided password matches the stored hashed password
            if check_password(user['password'], password):
                session['user'] = user['udiseCode']
                print("Login successful, redirecting to dashboard")
                return redirect(url_for('progress_school'))
            else:
                print("Invalid UDISE code or password")
                flash('Invalid UDISE code or password', 'danger')
                return render_template('login.html'), 401
        else:
            print("User not found")
            flash('Invalid UDISE code or password', 'danger')
            return render_template('login.html'), 401

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        udise_code = request.form['udiseCode']
        user = users.find_one({'udiseCode': udise_code})

        if user:
            try:
                otp = str(random.randint(100000, 999999))
                if 'email' in user:
                    users.update_one({'udiseCode': udise_code}, {'$set': {'otp': otp}})
                    session['udiseCode'] = udise_code  # Set UDISE code in session
                    print(f"OTP generated: {otp}")
                    print(f"Sending OTP to email: {user['email']}")
                    send_email(user['email'], otp)
                    return redirect(url_for('otp_verification'))
                else:
                    raise KeyError("Email field is missing in the user document.")
            except KeyError as ke:
                print(f"Key error: {ke}")
                flash('The email address is missing in the user document. Please contact support.', 'danger')
            except Exception as e:
                print(f"Error during OTP generation or sending email: {e}")
                flash('Failed to generate OTP or send email. Please try again.', 'danger')
                return redirect(url_for('register'))
        else:
            flash('UDISE number not found', 'danger')

    return render_template('register.html')


@app.route('/otp', methods=['GET', 'POST'])
def otp_verification():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        udise_code = session.get('udiseCode')
        user = users.find_one({'udiseCode': udise_code, 'otp': entered_otp})

        if user:
            # Set the UDISE code in the session for password setting
            session['udiseCode'] = udise_code
            return redirect(url_for('set_password'))
        else:
            flash('Invalid OTP', 'danger')

    return render_template('otp.html')


@app.route('/loginall', methods=['GET', 'POST'])
def loginall():
    return render_template('login for all modulres.html')


@app.route('/loginadmin', methods=['GET', 'POST'])
def loginadmin():
    return render_template('login_admin.html')


@app.route('/set-password', methods=['GET', 'POST'])
def set_password():
    if request.method == 'POST':
        try:
            # Fetching the form data using the name attributes
            password = request.form.get('password')
            confirm_password = request.form.get('confirmPassword')

            # Check if the password fields are empty
            if not password or not confirm_password:
                raise ValueError("Password or Confirm Password not provided")

            # Check if passwords match
            if password == confirm_password:
                # encrypted_password = encrypt_password(password)
                hashed_password = hash_password(password)
                print(f"Hashed Password: {hashed_password}")  # Debug print

                # Get the UDISE code from session
                udise_code = session.get('udiseCode')
                print(f"UDISE Code from session: {udise_code}")  # Debug print

                # Ensure UDISE code is present
                if not udise_code:
                    raise ValueError("UDISE Code is missing from session")

                # Check if the document exists and update the password
                result = users.update_one({'udiseCode': udise_code}, {'$set': {'password': hashed_password}})
                print(f"Update result: {result.modified_count} document(s) updated")  # Debug print

                if result.modified_count == 0:
                    raise ValueError("No document found with the provided UDISE Code")

                return redirect(url_for('login'))
            else:
                flash('Passwords do not match', 'danger')

        except KeyError as ke:
            print(f"Form key error: {ke}")
            flash('A required field is missing. Please try again.', 'danger')
        except ValueError as ve:
            print(f"Value error: {ve}")
            flash(str(ve), 'danger')
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            flash('An error occurred while setting the password. Please try again.', 'danger')

    return render_template('set_password.html')


@app.route('/otp')
def otp():
    return render_template('otp.html')


@app.route('/map')
def map():
    return render_template('map.html')


@app.route('/dashboard')
def dashboard():
    try:
        print("Session data:", session)
        udise_code = session.get('user')
        print(udise_code)
        if not udise_code:
            flash("Session expired, please log in again.", "danger")
            return redirect(url_for('login'))

        # Fetch school data or any other operation
        school = users.find_one({'udiseCode': udise_code})

        # Pass data to the template
        return render_template('ai_tool.html', school=school)
    except Exception as e:
        print(f"Error: {e}")
        flash("An unexpected error occurred. Please try again later.", "danger")
        return render_template('error.html'), 500  # Ensure error.html exists


@app.route('/progress_school', methods=['GET', 'POST'])
def progress_school():
    return render_template('progress-dashboard-school.html')


@app.route('/school_user', methods=['GET', 'POST'])
def school_user():
    return render_template('school-user-dashboard.html')


@app.route('/progress_dashboard', methods=['GET', 'POST'])
def progress_dashboad():
    return render_template('progressing-monitoring-dashboard.html')


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    return render_template('admin-dashboard.html')


@app.route('/resource_allocation', methods=['GET', 'POST'])
def resource_allocation():
    return render_template('resources-admin.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/community')
def community():
    return render_template('community.html')

if __name__ == '__main__':
    app.run(debug=True)
