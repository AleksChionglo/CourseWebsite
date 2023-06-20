import sqlite3
import hashlib
import os
from functools import wraps
from flask import Flask, session, redirect, url_for, request, escape, render_template, g

DATABASE = './assignment3.db'

# Web App Config
app = Flask(__name__, static_url_path='/static')

app.secret_key = os.urandom(12)

# Database functions
# functions get_db, make_dicts, close_connection, query_db are take from here
# https://flask.palletsprojects.com/en/1.1.x/patterns/sqlite3/


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# Other helpers
# functions login_required are take from here
# https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/#login-required-decorator


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('root'))
        return f(*args, **kwargs)
    return decorated_function

# Request Handlers


@app.route("/", methods=['GET', 'POST'])
def root():
    if request.method == "POST":
        db = get_db()
        db.row_factory = make_dicts

        user_name = request.form['username']
        password_candidate = request.form['password']
        user = query_db("SELECT * FROM AccountCredentials WHERE Username = :user",
                        {'user': user_name}, one=True)
        if user and user["Username"] == user_name:
            hashed_pass = hashlib.sha256(
                password_candidate.encode()).hexdigest()
            if hashed_pass == user["Password"]:
                # logged in
                session['username'] = user_name
                return redirect(url_for('home'))
            else:
                return render_template("index.html", error="Invalid password")
        else:
            return render_template("index.html", error="Cannot find username, did you make an account?")
    elif 'username' in session:
        return redirect(url_for('home'))
    elif request.method == "GET":
        return render_template("index.html")


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        account_type = request.form['accountType']
        first_name = request.form['firstname']
        last_name = request.form['lastname']
        user_name = request.form['username']
        password_candidate = request.form['password1']
        password_repeat = request.form['password2']

        #Backend form validation
        if account_type != "Instructor" and account_type != "Student":
            return render_template("register.html", error="Must be a Student or Instructor")

        if any(not c.isalnum() for c in first_name):
            return render_template("register.html", error="First name contains non-alphabetical characters")

        if any(not c.isalpha() for c in last_name):
            return render_template("register.html", error="Last name contains non-alphabetical characters")

        if any(not c.isalnum() for c in user_name):
            return render_template("register.html", error="Username contains special characters")

        if password_candidate != password_repeat:
            return render_template("register.html", error="Passwords do not match")

        if len(password_candidate) < 6:
            return render_template("register.html", error="Password less than 6 characters")

        db = get_db()
        db.row_factory = make_dicts
        #check if the username already exists
        user = query_db("SELECT * FROM AccountCredentials WHERE Username = :user",
                        {'user': user_name}, one=True)
        if not user:
            hashed_pass = hashlib.sha256(
                password_candidate.encode()).hexdigest()
            cur = db.cursor()
            cur.execute("""INSERT INTO 
            AccountCredentials 
            (Username,
            Password,
            AccountNumber,
            AccountType,
            FirstName,
            LastName,
            "UnhashedPassword(DELETE)")
            VALUES(?, ?, ?, ?, ?, ?, ?)""",
                       (user_name, hashed_pass, None, account_type, first_name, last_name, password_candidate))
            #save changes
            db.commit()
            
            #automatically log in
            session['username'] = user_name
            return redirect(url_for('home'))
        else:
            return render_template("register.html", error="Username taken")
    elif 'username' in session:
        return redirect(url_for('home'))
    elif request.method == "GET":
        return render_template("register.html")


@ app.route("/signout")
@ login_required
def signout():
    session.clear()
    return redirect(url_for('root'))


@ app.route("/home")
@ login_required
def home():
    if 'username' in session:
        return render_template("home.html", User=escape(session["username"]))
    return redirect(url_for('root'))


@ app.route("/calendar")
@ login_required
def calendar():
    return render_template("calendar.html")


@ app.route("/assignments")
@ login_required
def assignments():
    return render_template("assignments.html")


@ app.route("/weekly")
@ login_required
def weekly():
    return render_template("weekly.html")


@ app.route("/links")
@ login_required
def links():
    return render_template("links.html")


if __name__ == "__main__":
    app.run(debug=True)
