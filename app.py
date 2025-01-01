from flask import Flask, render_template, url_for, session, redirect, request
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()
app.secret_key = os.getenv('SECRET_KEY', '')

client = MongoClient('mongodb://localhost:27017/')
db = client.mydatabase
users_collection = db['users']

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id='ClientId',
    client_secret='ClientSecret',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

with app.app_context():
    users_collection.create_index("username", unique=True)
    users_collection.create_index("email", unique=True)

# Home page route
@app.route('/', methods=['GET', 'POST'])
def home():
    auth = session.get('auth', 0)
    return render_template('index.html', auth=auth)

# Google login route
@app.route('/google')
def google_login():
    redirect_uri = url_for("authorize_google", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/authorize/google")
def authorize_google():
    token = google.authorize_access_token()
    resp = google.get("userinfo")
    user_info = resp.json()

    userID = user_info.get("email")

    # Check if user already exists, if not, insert into usersCollection
    if not users_collection.find_one({"email": userID}):
        new_user = {
            "username": user_info.get("given_name"),  # Or any other user info you want to store
            "email": userID,
            "password": None  # No password for Google OAuth users
        }
        users_collection.insert_one(new_user)

    session['auth'] = 1
    session['email'] = userID
    session['username'] = user_info.get("given_name")  # Or store any other identifier you prefer
    return redirect(url_for('home'))

# Sign up route
@app.route('/signin', methods=['POST', 'GET'])
def signin():

    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        existing_email = users_collection.find_one({"email": email})
        existing_username = users_collection.find_one({"username": username})

        if existing_email:
            message = "*Account already exists :)"
            return render_template('signin.html', message=message)
        elif existing_username:
            message = "*Username already taken :)"
            return render_template('signin.html', message=message)

        hashed_password = generate_password_hash(password)
        new_user = {
            "username": username,
            "email": email,
            "password": hashed_password
        }
        users_collection.insert_one(new_user)
        session['auth'] = 1
        session['username'] = username
        session['email'] = email
        return redirect(url_for('home'))

    return render_template('signin.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find the user by username
        user = users_collection.find_one({"username": username})

        if user and check_password_hash(user['password'], password):
            session['auth'] = 1
            session['username'] = username
            return redirect(url_for('home'))
        else:
            message = 'Invalid username or password!'
            return render_template('login.html', message=message)

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True, port=5050)
