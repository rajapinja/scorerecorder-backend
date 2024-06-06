from flask import Flask, session, redirect, url_for

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # This should be a long and secure secret key

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()  # Clear the user's session
    return redirect(url_for('index'))  # Redirect to a different page after logout

@app.route('/')
def index():
    if 'user_id' in session:
        # User is logged in
        return f"Welcome, User {session['user_id']}!"
    else:
        return "Welcome to the app. Please log in."

if __name__ == '__main__':
    app.run()
