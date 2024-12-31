from flask import Flask, render_template, url_for, session, redirect, request
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os

# Initialize Flask app
app = Flask(__name__)

# Load environment variables
load_dotenv()
print("Google Client ID:", os.getenv('GOOGLE_CLIENT_ID'))
print("Google Client Secret:", os.getenv('GOOGLE_CLIENT_SECRET'))
print("Secret Key:", os.getenv('SECRET_KEY'))
# Secret key for session management
app.secret_key = os.getenv('SECRET_KEY', '')

# MongoDB connection setup
client = MongoClient('mongodb://localhost:27017/')
db = client.mydatabase
users_collection = db['users']

# OAuth setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='CLIENT ID',
    client_secret='SECRET ID',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    refresh_token_url=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'},
)

# MongoDB index creation for unique username and email
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
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

# Google OAuth callback route
@app.route('/google/callback')
def google_callback():
    token = google.authorize_access_token()  # Exchange code for access token
    user_info = google.get('userinfo').json()  # Get user info from Google API

    # Check if required keys exist in the user_info
    username = user_info.get('name', 'Unnamed')  # Default to 'Unnamed' if name doesn't exist
    email = user_info.get('email', '')

    if not email:
        return "Error: Email not returned from Google."

    # Check if the user already exists
    existing_user = users_collection.find_one({"email": email})

    if not existing_user:
        # If the user doesn't exist, create a new user
        new_user = {
            "username": username,
            "email": email,
            "google_id": user_info['id']
        }
        users_collection.insert_one(new_user)

    # Save user info to the session
    session['auth'] = 1
    session['username'] = username
    session['email'] = email

    return redirect(url_for('home'))

# Sign up route
@app.route('/signin', methods=['POST', 'GET'])
def signin():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if email or username already exists
        existing_email = users_collection.find_one({"email": email})
        existing_username = users_collection.find_one({"username": username})

        if existing_email:
            message = "*Account already exists :)"
            return render_template('signin.html', message=message)
        elif existing_username:
            message = "*Username already taken :)"
            return render_template('signin.html', message=message)

        # Create new user
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
