from flask import Flask, render_template, url_for, session, redirect, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SECRET_KEY'] = 'OQKCNEJXJEJXL'
db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    userid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

# Initialize the database
with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def home():
    auth = session.get('auth', 0)
    return render_template('index.html', auth=auth)

@app.route('/signin', methods=['POST', 'GET'])
def signin():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Check for existing user
        existingUsername = User.query.filter_by(username=username).first()
        existingEmail = User.query.filter_by(email=email).first()
        if existingEmail:
            message = "*Account already exists :)"
            return render_template('signin.html', message=message)
        elif existingUsername:
            message = "*Username already taken :)"
            return render_template('signin.html', message=message)
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()
            session['auth'] = 1
            session['username'] = username
            session['email'] = email
            return redirect(url_for('home'))
    return render_template('signin.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['auth'] = 1
            session['username'] = username
            return redirect(url_for('home'))
        else:
            message = 'Invalid username or password!'
            return render_template('login.html', message=message)

    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True, port=5050)
