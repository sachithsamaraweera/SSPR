from flask import Flask, redirect, url_for, render_template, request, session
from pyad import *
import threading
import pythoncom
import smtplib
from email.mime.text import MIMEText
import random
import re
import html
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import asc,desc
import datetime
import os



app = Flask(__name__)
app.secret_key = 'random_string'
global_uname = "abc"
global_otp = "111"

pyad.set_defaults(ldap_server="kln.ac.lk", username="Administrator", password="Admin@123")

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@localhost/pw_logs"
db = SQLAlchemy(app)
app.app_context().push()

class Users(db.Model):
    __tablename__ = "pw_history"  # Specify the name of the table in the database

    reset_id = db.Column(db.Integer, primary_key=True)  # Add a primary key column
    cn = db.Column(db.String(100))
    email = db.Column(db.String(100))
    datetime = db.Column(db.DateTime)
    Expire_on = db.Column(db.DateTime)

    def __init__(self, cn, email, datetime, Expire_on):
        self.cn = cn
        self.email = email
        self.datetime = datetime
        self.Expire_on = Expire_on

dt = datetime.datetime.now()
formatted_datetime = dt.strftime("%Y-%m-%d %H:%M:%S")
Expire_date = dt + datetime.timedelta(days=30)


def initialize_com():
    pythoncom.CoInitialize()

def uninitialize_com():
    pythoncom.CoUninitialize()

def send_otp(email, otp):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "sachithatwork@gmail.com"
    smtp_password = "qbatwwdrymivcfsk"
    subject = "OTP for login"
    body = f"Your OTP is: {otp}"
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = smtp_username
    message["To"] = email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(message)

def sanitize_input(input_string):
    sanitized_string = re.sub(r'[^a-zA-Z0-9@._\s-]', '', input_string)
    sanitized_string = html.escape(sanitized_string)
    return sanitized_string

@app.route("/")
def index():
    session["otp_validation"]=False
    return render_template("index.html")

@app.route("/", methods=["POST"])
def getuname():
    username = sanitize_input(request.form["username"])
    global global_uname
    print(username)
    email = sanitize_input(request.form["email"])
    print(email)
    initialize_com()

    try:
        user = pyad.aduser.ADUser.from_cn(username)
        print(user)
        email_attribute = user.get_attribute("mail")
        email_attribute=str(email_attribute[0])
        if email_attribute == email:
            otp = random.randint(100000, 999999)
            global global_otp
            global_otp = otp
            send_otp(email, otp)
            print(f"OTP is : {otp}")
            # Save OTP to session
            session["xValid"]= True
            session["email"]=email_attribute
            global_uname = username
            return redirect(url_for('otp_form'))
        else:
            print("Email is not valid")
            uninitialize_com()
            return render_template('invalid.html', error="Invalid")
    except Exception:
        return render_template('invalid.html', error="Invalid")
@app.route("/otp_form", methods=["GET", "POST"])
def otp_form():
    if request.method == "POST":
        print(request.form["OTP"])
        otp_entered = request.form["OTP"]
        
        if otp_entered is None:
            return "No OTP provided", 400
        if otp_entered == str(global_otp):
            session["otp_validation"]=True
            return redirect(url_for("reset_password"))
        else:
            return render_template('otp_invalid.html'), 401
    else:
        if("xValid" in session):
            if(session["xValid"]):
                return render_template('otp_form.html')
            else:
                return render_template("session_expired.html")

        else:
            return render_template("direct_access.html")
@app.route("/reset_password", methods=["POST","GET"])
def reset_password():
    if request.method == "POST":
        if("Reset" in request.form):
            password = sanitize_input(request.form["password"])
            confirm_password = sanitize_input(request.form["confirm_password"])

            if password == confirm_password:
                username = global_uname
                print("password matching")
                reset_success = reset_password_in_ldap(username, password)  # replace with your LDAP password reset function
                if reset_success:
                    db.session.add(Users(global_uname, session["email"], formatted_datetime,Expire_date))
                    db.session.commit()
                    session["xValid"] = False
                    return render_template('reset_success.html')
                
                else:
                    return render_template('reset_failed.html'), 500
            else:
                return render_template('reset_mismatch.html'), 400
        elif("Unlock" in request.form):
            username = global_uname
            unlock_pass = unlock_acc_in_ldap(username)
            if unlock_pass:
                return render_template("unlock_success.html")
            else:
                return "ERROR"
        elif("pwdhistory" in request.form):
            username = global_uname
            result = Users.query.filter(Users.cn == username).order_by(desc(Users.datetime)).all()
            current_d = formatted_datetime
            if result:
                return render_template("password_history.html",entries=result,current_d=current_d)
            else:
                return "ERROR"  
    else:
        if("otp_validation" in session):
            if(session["otp_validation"]==True):
                # session.clear()
                return render_template("reset_password.html")
                
            else:
                return render_template("direct_access.html") 
        else:
            return render_template("direct_access.html")
        

def reset_password_in_ldap(username, new_password):
    initialize_com()
    user = pyad.aduser.ADUser.from_cn(username)
    try:
        user.set_password(new_password)
        uninitialize_com()
        return True
    except Exception as e:
        print(f"Error resetting password: {e}")
        uninitialize_com()
        return False

def unlock_acc_in_ldap(username):
    initialize_com()
    user = pyad.aduser.ADUser.from_cn(username)
    try:
        user.unlock()
        uninitialize_com()
        return True
    except Exception as e:
        print(f"Error resetting password: {e}")
        uninitialize_com()
        return False


@app.route("/password_policy")
def ppolicy():
    return render_template("password_policy.html")

@app.route("/password_history")
def phistory():
    return render_template("password_history.html")



if __name__ == "__main__":
    app.run(host="0.0.0.0",debug=True, port=50100, ssl_context=('cert.pem', 'key.pem'))
