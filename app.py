from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from utils import valid_field, get_user
import os, bcrypt

app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:hello@localhost/wiki"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
db=SQLAlchemy(app)
app.secret_key="2314lmnlfm0q394flwa"
split="25/xz>"

class Page(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.Text(), nullable=False, unique=True)
    content=db.Column(db.Text(), nullable=False)
    users=db.Column(db.Text())
    def __init__(self, title, content, users):
        self.title=title
        self.content=content
        self.users=users
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
    return render_template('home.html', title='Home', user=get_user(request.cookies.get('username_cookie')))

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
        return render_template('login.html', error="The username or password you entered is not valid!",
        title='Login', user=get_user(request.cookies.get('username_cookie')))
    else:
        return render_template('login.html', title='Login', user=get_user(request.cookies.get('username_cookie')))

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
            return render_template('signup.html', title='Signup', user=get_user(request.cookies.get('username_cookie')))
        else:
            d={}
            d['title']='Signup'
            d['user'] = get_user(request.cookies.get('username_cookie'))
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
        return render_template('signup.html', title='Signup', user=get_user(request.cookies.get('username_cookie')))

@app.route('/logout')
def signout():
    resp=redirect(url_for('home'))
    resp.set_cookie('username_cookie', '', expires=0)
    flash("You have been logged out.")
    return resp

@app.route('/wiki/<page_title>/edit', methods=['GET', 'POST'])
def edit(page_title):
    user=get_user(request.cookies.get('username_cookie'))
    page=db.session.query(Page).filter_by(title=page_title).first()
    if not user:
        flash('You must be signed in to make edits.')
        return render_template('view.html', title=page_title, content=page.content, user=user)

    stored_user = db.session.query(User).filter_by(username=user).first()
    if stored_user:
        if stored_user.password_hash.decode('utf-8') != request.cookies.get('username_cookie').split(',')[1]:
            flash('There was a problem authenticating your identity. Please try logging in again.')
            return render_template('view.html', title=page_title, content=page.content, user=user)

    if request.method=='GET':
        if page:
            return render_template('edit.html',page_title=page_title, title='Edit '+page_title, saved_content=page.content, user=user)
        else:
            return render_template('edit.html',page_title=page_title, title='Edit '+page_title, user=user)
    else:
        content=request.form.get('content')
        if not content:
            flash("You did not enter valid content.")
            if page:
                return render_template('edit.html',page_title=page_title, title='Edit '+page_title, saved_content=page.content, user=user)
            else:
                return render_template('edit.html',page_title=page_title, title='Edit '+page_title, user=user)
        if page:
            page.content=page.content+split+content
            page.users=page.users+split+user
        else:
            page=Page(page_title, content, user)
            db.session.add(page)
        db.session.commit()
        return redirect('/wiki/'+page_title)

@app.route('/wiki/<page_title>/history')
def history(page_title):
    user=get_user(request.cookies.get('username_cookie'))
    page=db.session.query(Page).filter_by(title=page_title).first()
    if not page:
        return 'The title you specified does not exist!'
    else:
        versions=page.content.split(split)
        users=page.users.split(split)
        return render_template('history.html',title=page_title+' History', user=user, users=users, versions=versions, name=page_title)

@app.route('/wiki/<page_title>')
def view(page_title):
    user=get_user(request.cookies.get('username_cookie'))
    page=db.session.query(Page).filter_by(title=page_title).first()
    if page:
        content=page.content.split(split)[-1]
        return render_template('view.html', title=page_title, content=content, user=user)
    else:
        return redirect('/wiki/'+page_title+'/edit')

@app.route('/wiki/')
def wiki():
    pages=db.session.query(Page).order_by(Page.title.desc()).all()
    user=get_user(request.cookies.get('username_cookie'))
    return render_template('wiki.html', title='Directory', pages=pages, user=user)


if __name__ == '__main__':
	port = int(os.environ.get('PORT', 5000))
	app.run(host='0.0.0.0', port=port)
