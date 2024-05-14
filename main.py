from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from pymongo import MongoClient
import requests
from textblob import TextBlob
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os
import certifi
ca = certifi.where()


uri = "mongodb+srv://mindfull:sushi12345@cluster0.pfv0xgr.mongodb.net/?retryWrites=true&w=majority"

# Create a new client and connect to the server
client = MongoClient(uri, tlsCAFile=ca)

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("MongoDB connection is successful!")
except Exception as e:
    print(e)

db = client['logininfo']
users_collection = db['users']

def analyze_sentiment(text):
    blob = TextBlob(text)
    sentiment_score = blob.sentiment.polarity

    if sentiment_score > 0:
        return 'Positive'
    elif sentiment_score < 0:
        return 'Negative'
    else:
        return 'Neutral'

def generate_response(journal_entry):
    # Define some rules based on journal content
    if analyze_sentiment(journal_entry) == "Positive":
        return "I'm glad that you're feeling happy!"
    elif analyze_sentiment(journal_entry) == "Negative":
        return "It's ok to feel down sometimes."
    else:
        return "I hope you had a great day today!"

# randomised quotes from codecollab
outputi = "The graveyard is the richest place on earth, because it is here that you will find all the hopes and dreams that were never fulfilled, the books that were never written, the songs that were never sung, the inventions that were never shared, the cures that were never discovered, all because someone was too afraid to take that first step, keep with the problem, or determined to carry out their dream. ~Les Brown"
outputw = "She could hear, some way off, her brothers calling to each other in the woods behind the house. She hoped desperately that their game wouldn't bring them any closer, that they wouldn't scare the birds away ~Neil Gaiman"
outputm = "Dream as if you will live forever; Live as if you will die today. ~James  Dean"

daily_quote = "In the end, you feel that your much-vaunted, inexhaustible fantasy is growing tired, debilitated, exhausted, because you're bound to grow out of your old ideals; they're smashed to splinters and turn to dust, and if you have no other life, you have no choice but to keep rebuilding your dreams from the splinters and dust. But the heart longs for something different! And it is vain to dig in the ashes of your old fancies, trying to find even a tiny spark to fan into a new flame that will warm the chilled heart and bring back to life everything that can send the blood rushing wildly through the body, fill the eyes with tears--everything that can delude you so well! ~Fyodor Dostoevsky"

app = Flask(__name__)
app.secret_key = os.urandom(24) # use a strong, random secret key

# MongoDB connection string and database details
db_name = 'logininfo'
collection_name = 'users'

# Connect to MongoDB
db = client[db_name]
collection = db[collection_name]

@app.route('/')
def index():
    url = 'http://api.weatherapi.com/v1/current.json?key=758757ab922149d3a47123611232908&q=Singapore&aqi=no'
    response = requests.get(url)
    json_data = response.json()
    temperature = json_data["current"]["temp_c"]
    return render_template('index.html', daily_quote=daily_quote, outputi=outputi, outputm=outputm, outputw=outputw, temperature=temperature)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            # Extract the login data from the form
            username = request.form['username']
            password = request.form['password']

            # Find user by username
            user = collection.find_one({'username': username})

            if user:
                # Get stored salt and encrypted password
                stored_salt = base64.b64decode(user['salt'])
                stored_encrypted_password = user['password']

                # Generate key and decrypt stored password
                key = generate_key(password, stored_salt)
                decrypted_password = decrypt_message(key, stored_encrypted_password)

                # Check if passwords match
                if decrypted_password == password:
                    session['username'] = username
                    print("Login successful")
                    return redirect('/')
                else:
                    print("Invalid username or password")
            else:
                print("Invalid username or password")
            return jsonify({'error': 'Invalid username or password'}), 400
        except Exception as e:
            print('Error during login:', e)
            return jsonify({'error': 'An error occurred'}), 500
    return render_template('login.html')

# Function to generate a key from a password using PBKDF2
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to encrypt data using AES
def encrypt_message(key, message):
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt_message(key, encrypted_message):
    f = Fernet(key)
    return f.decrypt(encrypted_message.encode()).decode()

@app.route('/signup', methods=['POST', 'GET'])
def sign_up():
    if request.method == "POST":
        try:
            # Get form data from the request
            username = request.form['username']
            password = request.form['password']
            repassword = request.form['repassword']

            print(f"Received data - Username: {username}, Password: {password}, Repassword: {repassword}")

            # Check if passwords match
            if password != repassword:
                print("Passwords do not match")
                return jsonify({'error': 'Passwords do not match'}), 400

            # Generate a random salt
            salt = os.urandom(16)
            print(f"Generated salt: {salt}")

            # Generate key and encrypt password
            key = generate_key(password, salt)
            encrypted_password = encrypt_message(key, password)
            print(f"Generated key: {key}, Encrypted password: {encrypted_password}")

            # Store user data in MongoDB
            collection.insert_one({
                'username': username,
                'password': encrypted_password,
                'salt': base64.b64encode(salt).decode()
            })

            print("User data saved successfully")
            return jsonify({'message': 'User data saved successfully'})
        except Exception as e:
            print('Error during sign-up:', e)
            return jsonify({'error': 'An error occurred'}), 500
    return render_template('signup.html')

@app.route('/journal', methods=['GET'])
def journal():
  return render_template("journal.html", daily_quote=daily_quote, outputi=outputi, outputm=outputm, outputw=outputw)

@app.route('/journal', methods=['GET', 'POST'])
def analyze():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            journal_entry = request.form['journalEntry']
            mood = analyze_sentiment(journal_entry)
            response = generate_response(journal_entry)
            return render_template('journal.html', mood=mood, response=response, daily_quote=daily_quote, outputi=outputi, outputm=outputm, outputw=outputw)
        except Exception as e:
            print('Error during sentiment analysis:', e)
            return jsonify({'error': 'An error occurred'}), 500

    return render_template("journal.html", daily_quote=daily_quote, outputi=outputi, outputm=outputm, outputw=outputw)

@app.route('/save_quote', methods=['POST'])
def save_quote():
    try:
        quote = request.form['quote']
        # Here, you can implement code to save the quote into a list or database.
        # For example, you can store it in a MongoDB collection.
        # collection.insert_one({'quote': quote})
        collection.update_one({"username": session['username']},
{"$set": {"quote": quote}})

        return jsonify({'message': 'Quote saved successfully', 'quote': quote})
    except Exception as e:
        print('Error saving quote:', e)
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/logout')
def logout():
    session['username'] = None  # Clear all data from the session
    return redirect('/')  # Redirect to the login page or home page

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=81)
