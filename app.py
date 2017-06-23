from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from utils import valid_field
import os, bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:hello@localhost/wiki"
db=SQLAlchemy(app)
app.secret_key="2314lmnlfm0q394flwa"

class Page(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.Text(), nullable=False, unique=True)
    content=db.Column(db.Text(), nullable=False)
    def __init__(self, title, content):
        self.title=title
        self.content=content
    def __repr__(self):
        return self.title+' Page'

class User(db.Model):
    username=db.Column(db.Text(), primary_key=True)
    password_hash=db.Column(db.LargeBinary(), nullable=False)
    def __init__(self, username, password_hash):
        self.username=username
        self.password_hash=password_hash
    def __repr__(self):
        return self.username

db.create_all()
db.session.commit()

@app.route('/')
def home():
    username=request.cookies.get('username_cookie')
    if username:
        username=username.split(',')[0]
    return render_template('home.html', title='Home', user=username)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password'].encode('utf-8')
        account=User.query.filter_by(username=username).first()
        if account:
            hashed=account.password_hash
            if bcrypt.checkpw(password, hashed):
                resp=redirect(url_for('home'))
                resp.set_cookie('username_cookie', account.username+','+hashed.decode('utf-8'))
                return resp

        user=request.cookies.get('username_cookie')
        if user:
            user=user.split(',')[0]
        return render_template('login.html', error="The username or password you entered is not valid!",
        title='Login', user=user)
    else:
        user=request.cookies.get('username_cookie')
        if user:
            user=user.split(',')[0]
        return render_template('login.html', title='Login', user=user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method=='POST':
        username = request.form.get('username')
        password = request.form.get('password')
        verified = request.form.get('verified')
        username_flag = valid_field(username, 'username')
        password_flag = valid_field(password, 'password')
        verified_flag = password != None and password == verified
        exists_flag = User.query.filter_by(username=username).first() == None

        if username_flag and password_flag and verified_flag and exists_flag:
            password_hash=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user=User(username, password_hash)
            db.session.add(new_user)
            db.session.commit()
            flash("You have successfully created an account!")
            return render_template('signup.html', title='Signup', user=username)
        else:
            d={}
            d['title']='Signup'
            user=request.cookies.get('username_cookie')
            if user:
                user=user.split(',')[0]
            d['user'] = user
            if not exists_flag:
                d['exists_error'] = "That username already exists!"
            if not username_flag:
                d['username_error'] = "Username must consist of only alphanumeric characters"
            if not password_flag:
                d['password_error'] = "Password must be between 3-20 characters"
            if not verified_flag:
                d['verified_error'] = "Your passwords don't match!"
            return render_template('signup.html', **d)
    else:
        user=request.cookies.get('username_cookie')
        if user:
            user=user.split(',')[0]
        return render_template('signup.html', title='Signup', user=user)


@app.route('/logout')
def signout():
    resp=redirect(url_for('home'))
    resp.set_cookie('username_cookie', '', expires=0)
    flash("You have been logged out.")
    return resp



if __name__ == '__main__':
	port = int(os.environ.get('PORT', 5000))
	app.run(host='0.0.0.0', port=port)
