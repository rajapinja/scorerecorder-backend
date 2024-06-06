from flask import Flask, request, jsonify, g, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_caching import Cache
import secrets
import mysql.connector
import bcrypt
import datetime
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin, logout_user
from user_roles import user_roles
from user_roles import insert_users_roles, user_already_exists, get_user_id, get_users_roles_role_id, get_role
from max_roundnumber import get_max_roundNumber
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl


#from db import query_db

#Swagger Stuff
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint

app = Flask(__name__)
CORS(app)

cache = Cache(app)

# Register the blueprints ( )
app.register_blueprint(user_roles)
#app.register_blueprint(timer)

app.secret_key = secrets.token_hex(16) 
# Generate and set the JWT secret key
#app.config['JWT_SECRET_KEY'] = secrets.token_hex(16)  
# Initialize JWTManager after setting the secret key
jwt = JWTManager(app)

# Set a value to a global variable using app.config
#app.config['GLOBAL_ROUNDNUMBER'] = 0
login_manager = LoginManager(app)

# MySQL setup
db = mysql.connector.connect(
    host="scorerecoder.c348gyc8yhgg.us-east-1.rds.amazonaws.com",
    user="admin",
    password="admin123",
    database="scorerecorder"
)

password_reset_tokens = {}
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'password'
# app.config['MYSQL_DB'] = 'scorerecorder'

def load_user(user_id):
    # Implement the logic to retrieve a user from your data store based on user_id
    # For example, retrieve the user from your database
    try:
        cursor = db.cursor()
        cursor.execute('SELECT username FROM users WHERE username=%s', (user_id,))
        user_data = cursor.fetchone()      
        db.commit()
        cursor.close()        
        user = User(user_data[0])   
    except mysql.connector.IntegrityError as e:
        error_message = str(e)  # Extract the error message from the exception
        print(error_message)
        return jsonify({'error': error_message})
    
login_manager.user_loader(load_user)

#Define a User class that inherits from UserMixin and represents your users:
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Define the unauthorized response handler
@jwt.unauthorized_loader
def unauthorized_response(callback):
    print('Unauthorized')
    return jsonify(message='Unauthorized'), 401

# Define the invalid token response handler
@jwt.invalid_token_loader
def invalid_token_response(callback):
    print('Invalid token')
    return jsonify(message='Invalid token'), 401

# Define the expired token response handler
@jwt.expired_token_loader
def expired_token_response(expired_token):
    print('Token has expired')
    return jsonify(message='Token has expired'), 401

@app.route('/api/registration', methods=['POST'])
def registration():

    """
    User Registration Endpoint
    ---
    tags:
      - Player Registration
    post:
      summary: Register a new user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                userpassword:
                  type: string
                email:
                  type: string
                selectedRole:
                  type: string
      responses:
        200:
          description: Registration successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        400:
          description: Registration failed or user already exists
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
      parameters:
        - in: body
          name: user_data
          required: true
          description: JSON object containing user registration data
          schema:
            type: object
            properties:
              username:
                type: string
              userpassword:
                type: string
              email:
                type: string
              selectedRole:
                type: string
    """

    data = request.get_json()        
    user = data['username']
    userpassword = data['userpassword']   
    email = data['email'] 
    role = data['selectedRole'] 

    password_hash = bcrypt.hashpw(userpassword.encode('utf-8'), bcrypt.gensalt())
   
    try:

        if user_already_exists(db, user) :            
            return jsonify({'error': 'User already exists'}), 409 
        else:
            cursor = db.cursor()
            sql = "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)"
            val = (user, password_hash, email)
            cursor.execute(sql, val)

            #Insert password into password_history
            cursor.execute("INSERT INTO password_history (username, password_hash) VALUES (%s, %s)", (user, password_hash))
            
            db.commit()
            cursor.close()
            #Call users_roles table to update with user roles from users_roles module
            sucess = insert_users_roles(db, user, role)
            if sucess:              
                return jsonify({'message': 'Registration successful with '+sucess}), 200
            else:
                return jsonify({'error': 'Registration Failed with User and Role'}), 200  

   
    except mysql.connector.IntegrityError as e:
        error_code = e.errno  # Get the MySQL error code
        if error_code == 1062:
            error_message = "Duplicate entry. User already exists."
        else:
            error_message = "An error occurred during registration."

        return jsonify({"error": error_message}), 400    


#User Login without password expiration logic
@app.route('/api/userlogin', methods=['POST'])
def userlogin():
    """
    User Login Endpoint
    ---
    tags:
      - Player Login
    post:
      summary: Authenticate user and generate access token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                password:
                  type: string
      responses:
        200:
          description: Login successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                  user:
                    type: string
                  role:
                    type: string
                  accessToken:
                    type: string
        401:
          description: Invalid credentials
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
        404:
          description: User not found
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
      parameters:
        - in: body
          name: user_credentials
          required: true
          description: JSON object containing user credentials
          schema:
            type: object
            properties:
              username:
                type: string
              password:
                type: string
    """

    data = request.get_json()       
    user = data['username']
    password = data['password']

    try:
        cursor = db.cursor()       
       # Fetch user data from the database based on the username
        cursor.execute('SELECT password_hash FROM users WHERE username = %s', (user,))
        user_data = cursor.fetchone()
        db.commit()
        cursor.close()  
        if user_data[0] is not None:
            #print(user_data)
            # Encode the user-entered password as bytes
            user_password_bytes = password.encode('utf-8')

            if user_data:
                stored_password_hash = user_data[0]
                stored_password_hash = stored_password_hash.encode('utf-8')
                #if pbkdf2_sha256.verify(password, stored_password_hash):
                if bcrypt.checkpw(user_password_bytes, stored_password_hash):                
                    user_id = User(user)  # Replace with your actual user object
                    #login_user(user_id)                    

                    #get user_id by passing user to users table
                    user_id = get_user_id(db, user)                   
                    #print(user_id)
                    #get role_id by passing user_id to users_roles table
                    role_id = get_users_roles_role_id(db, user_id)
                    #print(role_id)
                    #get role from roles table by passing role_id
                    role = get_role(db, role_id)
                    #print(role)

                    access_token = generate_token_with_expiration(user_id)
                    #return jsonify(access_token=access_token), 200
                    #print("access_token : ",access_token)

                    return jsonify({
                        "message": "Login successful",
                        "user": user,
                        "role": role,
                        "accessToken":access_token,
                    }), 200                 

                else:
                    return jsonify({'error': 'Invalid credentials'}), 401
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'User not found'}), 404                           

    except mysql.connector.IntegrityError as e:
        error_message = str(e)  # Extract the error message from the exception
        print(error_message)
        return jsonify({'error': error_message})    
    
#User Login  with password expiration logic
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']

        cursor = db.cursor()

        # Fetch user data from the database based on the username
        cursor.execute('SELECT password_hash, created_at FROM users WHERE username = %s', (username,))
        user_data = cursor.fetchone()
        cursor.close()

        if user_data:
            stored_password_hash = user_data[0]
            created_at = user_data[1]

            # Encode the user-entered password as bytes
            user_password_bytes = password.encode('utf-8')

            # Check if the password has expired (e.g., set expiration to 15 days)
            expiration_time = created_at + datetime.timedelta(days=45)
            if datetime.datetime.utcnow() > expiration_time:
                return jsonify({
                    'error': 'Password has expired. Redirect to reset password screen.',
                    "user": username, 
                    "expiration_time":expiration_time
                    }), 401

            # Check the password using bcrypt
            if bcrypt.checkpw(user_password_bytes, stored_password_hash.encode('utf-8')):
                user_id = get_user_id(db, username)
                role_id = get_users_roles_role_id(db, user_id)
                role = get_role(db, role_id)
                access_token = generate_token_with_expiration(user_id)

                return jsonify({
                    "message": "Login successful",
                    "user": username,
                    "role": role,
                    "accessToken": access_token,
                    "expiration_time":expiration_time
                }), 200

            else:
                return jsonify({'error': 'Invalid credentials'}), 401
        else:
            return jsonify({'error': 'User not found'}), 404
  
    except Exception as e:
        return jsonify({'error': str(e)}), 500
   

#Get User Deatails like username, email, created_at
# Placeholder function for getting user data
def get_user_data(username):
    # Replace this function with your actual logic to fetch user data from the database
    # Return a tuple (id, email, user_created_at) if the user exists, or None if not found
    try:
        with db.cursor() as cursor:
            # Update the password in the users table
            cursor.execute('SELECT id, email, created_at FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()

            if result:
                return result
        return None
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Function to send an email
def send_email(recipient_email, subject, message):
    # Replace these values with your email server configuration

   try:
    email_host = 'smtp.gmail.com'
    email_port = 587
    email_username = 'raja.pinja@gmail.com'
    email_password = 'tote nidu erbj cmhk'
    sender_email = 'raja.pinja@gmail.com'

    # Create a MIME object
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    # Attach the message to the MIME object
    msg.attach(MIMEText(message, 'plain'))

    # Establish a connection to the SMTP server
    #print("Attempting to connect to the SMTP server...")
    with smtplib.SMTP(email_host, email_port) as server:
      # server.set_debuglevel(1)  # Enable debugging
      # server.starttls()  # Upgrade the connection to TLS
      # server.login(email_username, email_password)
      # Debugging statements
     
      #server = smtplib.SMTP(email_host, email_port)
      server.starttls(context=ssl.create_default_context())
      #print("Successfully connected to the SMTP server.")
      server.login(email_username, email_password)
      #print("Successfully logged in.")
      server.sendmail(sender_email, recipient_email, msg.as_string())      

      #print(f"Email sent successfully to {recipient_email}")
   except Exception as e:
      print(f"Error sending email: {str(e)}")

def send_yahoo_email(recipient_email, subject, messageFrom):
    
  # Yahoo SMTP server settings
  smtp_server = 'smtp.mail.yahoo.com'
  smtp_port = 587  # Use 465 if SSL is required
  smtp_username = 'raja_pinja@yahoo.com'
  smtp_password = 'lvcqrprrgutrrijr'

  # Sender and recipient email addresses
  sender_email = 'raja_pinja@yahoo.com'
  recipient_email = 'raja.pinja@gmail.com'

  # Create the MIME object
  message = MIMEMultipart()
  message['From'] = sender_email
  message['To'] = recipient_email
  message['Subject'] = subject

  # Attach body to the message
  message.attach(MIMEText(messageFrom, 'plain'))

  try:
      # Connect to the SMTP server
      server = smtplib.SMTP(smtp_server, smtp_port)
      #print("Connected to SMTP server")

      server.starttls()  # Use this line for a secure connection
      #print("TLS started")

      # Login to the Yahoo email account
      server.login(smtp_username, smtp_password)
      #print("Logged in")

      # Send the email
      server.sendmail(sender_email, recipient_email, message.as_string())

      #print("Email sent successfully!")

  except Exception as e:
      print(f"Error sending email: {e}")

  finally:
      # Quit the SMTP server
      server.quit()


#Reset Password if its more than 15 days, since its creation
def update_password(username, new_password_hash):
    try:
        cursor = db.cursor()
        # Update the password in the users table
        cursor.execute('UPDATE users SET password_hash = %s, created_at = CURRENT_TIMESTAMP WHERE username = %s', (new_password_hash, username))
        cursor.execute("UPDATE password_history SET password_hash = %s WHERE username = %s", (new_password_hash, username))
        db.commit()
        cursor.close()
        return True
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# To get user's created_at value
def get_user_creation_timestamp(user_id):
    try:
        with db.cursor() as cursor:
            # Execute the SELECT query
            cursor.execute('SELECT created_at FROM users WHERE id = %s', (user_id,))
            
            # Fetch the result
            result = cursor.fetchone()

            if result:
                # Assuming the 'created_at' field is in the first position of the result tuple
                return result[0]

        # Return a default timestamp if the user is not found (for demonstration purposes)
        return datetime.datetime(2022, 1, 1, 0, 0, 0)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


#Reset Password Request
@app.route('/api/reset_password_request', methods=['POST'])
def reset_password_request():
    try:
        #print("Inside..reset_password_request ")
        data = request.get_json()
        username = data.get('username')

        #print("Inside..reset_password_request username :", username)
        # Validate email and check if the user exists
        user_data = get_user_data(username)
        if not user_data:
            return jsonify({'error': 'User not found'}), 404

        id, email, user_created_at = user_data
        #print("Inside..reset_password_request  id : , email: , user_created_at :",  id, email, user_created_at)

        user_created_at = get_user_creation_timestamp(id)
        print(" user_created_at :",  user_created_at)

        # Check if the user's password has expired (e.g., set expiration to 15 days)
        #expiration_time = user_created_at + datetime.timedelta(days=15)
        expiration_time = user_created_at + datetime.timedelta(days=45)
        #print("Expiration time:", expiration_time) 

        if datetime.datetime.utcnow() > expiration_time:
            # Password has expired, generate a reset token
            token = secrets.token_urlsafe(32)
            #print("Inside datetime.datetime.utcnow() > expiration_time token:", token) 

            password_reset_tokens[token] = {'user_id': id, 'expiration_time': datetime.datetime.now() + datetime.timedelta(hours=1)}
            #print("password_reset_tokens[token]:", password_reset_tokens[token]) 
            # Send the reset link to the user's email
            recipient_email = email  # Replace with the actual user's email
            subject = 'Password Reset'
            message = f'Click the following link to reset your password: https://4c8f-49-43-228-253.ngrok-free.app/api/reset_password_confirm?token={token}&username={username}'

            # Call the function to send the email
            #send_email(recipient_email, subject, message)
            send_yahoo_email(recipient_email, subject, message)

            return jsonify({'message': 'Password reset link sent successfully'})

        else:
           # Password has not expired, allow resetting on the screen
            return jsonify({'message': 'You can reset your password on the screen.'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# To handle password rest for email link   
@app.route('/api/reset_password_confirm', methods=['GET', 'POST'])
def reset_password_confirm():
  try:
    if request.method == 'GET':
        # Get the token and username from the query parameters
        token = request.args.get('token')
        username = request.args.get('username')

        # Render the password reset confirmation page with a form
        return render_template('reset_password_form.html', token=token, username=username)

    elif request.method == 'POST':
        # Handle POST request (process the submitted data)
        data = request.form
        token = data.get('token')
        username = data.get('username')
        new_password = data.get('new_password')

        # Verify the reset token
        if token not in password_reset_tokens:
            return jsonify({'error': 'Invalid or expired reset token'})

        # Check if the user exists
        user_id = get_user_id(db, username)
        if user_id is None:
            return jsonify({'error': 'User not found'})

        # hash the Password using bcrypt
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        # Update the password in the users table       
        success = update_password(username, new_password_hash)

        if success:
            # Password successfully updated, remove the reset token
            del password_reset_tokens[token]
            return jsonify({'message': 'Password successfully updated'})

        else:
            return jsonify({'error': 'Failed to update password'})
        
  except Exception as e:
    print(f"Error in reset_password_confirm: {str(e)}")
    return jsonify({'error': 'Internal Server Error'}), 500

# Reset Password Confirm
@app.route('/api/reset_password_confirm_older', methods=['GET', 'POST'])
def reset_password_confirm_older():
    try:
        data = request.get_json()
        token = data.get('token')
        username = data.get('username')
        new_password = data.get('new_password')

        # Verify the reset token
        if token not in password_reset_tokens:
            return jsonify({'error': 'Invalid or expired reset token'})

        # Check if the user exists
        user_id = get_user_id(username)
        if user_id is None:
            return jsonify({'error': 'User not found'})

        # Update the password in the users table       
        success = update_password(user_id, new_password.encode('utf-8'))

        if success:
            # Password successfully updated, remove the reset token
            del password_reset_tokens[token]
            return jsonify({'message': 'Password successfully updated'})

        else:
            return jsonify({'error': 'Failed to update password'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# To update expired password 
def update_reset_password(username, new_password_hash):          
  try:
      cursor = db.cursor()
      # Update the password in the users table, and insert the password into password_history
      # Execute the SQL query to update the password hash and created_at timestamp
      # query = 'UPDATE users SET password_hash = %s, created_at = CURRENT_TIMESTAMP WHERE username = %s'
      # params = (new_password_hash, username)
      cursor.execute("UPDATE users SET password_hash = %s, created_at = CURRENT_TIMESTAMP WHERE username = %s", (new_password_hash, username))
      cursor.execute("INSERT INTO password_history (username, password_hash) VALUES (%s, %s)", (username, new_password_hash))

      # cursor.execute(query, params)
      db.commit()
      cursor.close()
      print("Password and created_at updated successfully.")

  except Exception as e:
      db.rollback()
      #print("Error updating password and created_at:", e)     
      return jsonify({'error': str(e)}), 500 

def is_password_used(username, new_password_hash):
    cursor = db.cursor()
    # Replace this with your actual database query to check if the password exists in the password history   
    cursor.execute("SELECT COUNT(*) FROM password_history WHERE username = %s AND password_hash = %s", (username, new_password_hash))
    return cursor.fetchone()[0] > 0
    
# Reset Password if password expired less than 45 days
@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()

        # Assuming you include the necessary data like username and token
        username = data.get('username')
        new_password = data.get('newPassword')
        confirm_password = data.get('confirmPassword')

        # Validate that the passwords match
        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        # You can add more password strength validation if needed

        # Encode the user-entered password as bytes        
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        # Call the reset_password function
       
        # Check if the new password has been used before
        if is_password_used(username, new_password_hash):
            print("Password has been used before. Please choose a different password.")
        else:
            # Update the password and password history
            update_reset_password(username, new_password_hash)
            print("Password reset successful.")

        return jsonify({'message': 'Password reset successful'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

#Sample Protected route
@app.route('/api/protected', methods=['GET'])
@login_required
def protected():
    return jsonify({'message': f'Hello, {current_user.id}! This is a protected route.'})

@app.route('/api/logout', methods=['GET'])
#@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200

# API endpoint to add a player
@app.route('/api/add_player', methods=['POST'])
@jwt_required()
def add_player():

    """
    Add Player Endpoint
    ---
    tags:
      - Adding Player 
    post:
      summary: Add a new player
      security:
        - JWT: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                mobile:
                  type: string
      responses:
        200:
          description: Player added successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                  user:
                    type: string
        400:
          description: Failed to add player
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
      parameters:
        - in: body
          name: player_data
          required: true
          description: JSON object containing player information
          schema:
            type: object
            properties:
              name:
                type: string
              mobile:
                type: string
    """

    data = request.get_json()
    #name, age, dateOfBirth, qualification, assetsValue, party, address, district, state, country
    name = data['name']
    mobile = data['mobile']
    game_id = data['selectedGameId']

    jwt_login_user = get_jwt_identity() 
    print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

    #Check if game is in progress, check max round number, if it round number#1 , add player with initial score of 25, for each round
    message = insert_player_record(name, mobile, game_id)

    return jsonify({
                    "message": message,
                    "user":jwt_login_user,
                    })

#If Play is in progress, additional player can join by using this function
def insert_player_record(player_name, mobile_number, game_id):
    try:
        cursor = db.cursor()
        print("Inside insert_player_record")
        # Check if the record_scores table is empty
        cursor.execute("SELECT COUNT(*) FROM record_scores")
        record_count = cursor.fetchone()[0]
        print("Inside insert_player_record---record_scores")
        # Check for Max Game ID from games table 
        # cursor.execute("SELECT MAX(game_id) FROM games")
        # game_id = cursor.fetchone()[0]

        # Inserting record into players table
        insert_player_query = "INSERT INTO players (name, mobile, game_id) VALUES (%s, %s, %s)"
        cursor.execute(insert_player_query, (player_name, mobile_number, game_id))
        rtnPlayerMessage = " Player added successfully..!"
        db.commit()

        player_id = cursor.lastrowid  # Get the last inserted player_id

        if record_count > 0:
            # Fetching the max round number from record_scores table
            cursor.execute("SELECT MAX(round_number) FROM record_scores")
            max_round_number = cursor.fetchone()[0]

            # Inserting record into record_scores table based on max round number
            if max_round_number is not None:
                insert_record_scores_query = "INSERT INTO record_scores (player_id, round_number, score) VALUES (%s, %s, %s)"
                for round_num in range(1, max_round_number + 1):
                    cursor.execute(insert_record_scores_query, (player_id, round_num, 25))

                rtnRecordScoresMessage = "records insert into record_scores table successfully..!"
            db.commit()

        combined_message = rtnPlayerMessage + rtnRecordScoresMessage

        cursor.close()
        return combined_message    

    except mysql.connector.Error as error:
       return error
    

# API endpoint to add scores for a player, on each round
@app.route('/api/record_score', methods=['POST'])
@jwt_required()
def record_scores():

    """
    Record Scores Endpoint
    ---
    tags:
      - Record Scores
    security:
      - JWT: []
    post:
      summary: Add scores for a player on each round
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  player_id:
                    type: integer
                  round_number:
                    type: integer
                  score:
                    type: integer
      responses:
        200:
          description: Score recorded successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        500:
          description: An error occurred while recording the score
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """
    jwt_login_user = get_jwt_identity()       
    print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

    data_list = request.get_json()
    #print("data_list :",data_list)

    cursor = db.cursor()
    sql = "INSERT INTO record_scores (player_id, round_number, score) VALUES (%s, %s, %s)"
    
    for player_data in data_list:
        player_id = player_data['player_id']
        round_number = player_data['round_number']
        score = player_data['score']
        
        val = (player_id, round_number, score)
        cursor.execute(sql, val)
    
    db.commit()
    cursor.close()  
    
    return jsonify({"message": "Score recorded successfully"})

# API endpoint to update scores for a round/ player, on each round
@app.route('/api/update_score', methods=['POST'])
@jwt_required()
def update_scores():
    """
    Update Scores Endpoint
    ---
    tags:
      - Update Scores
    security:
      - JWT: []
    post:
      summary: Update scores for players on specified rounds
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  player_id:
                    type: integer
                  round_number:
                    type: integer
                  score:
                    type: integer
      responses:
        200:
          description: Scores updated successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        500:
          description: An error occurred while updating the scores
          content:

            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """

    jwt_login_user = get_jwt_identity()       
    print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

    data_list = request.get_json()
    print("data_list :",data_list)

    cursor = db.cursor()
    
    # Construct the SQL update statement
    sql = "UPDATE record_scores SET score = %s WHERE round_number = %s AND player_id = %s"

    for player_data in data_list:
        player_id = player_data['player_id']
        round_number = player_data['round_number']
        score = player_data['score']        
        val = (score, round_number, player_id)
        cursor.execute(sql, val)
    
    db.commit()
    cursor.close()  
    
    return jsonify({"message": "Score recorded successfully"})

@app.route('/api/players', methods=['GET'])
@jwt_required()
def get_players():
    """
    Players Endpoint
    ---
    tags:
      - Players
    security:
      - JWT: []
    get:
      summary: Get all players
      responses:
        200:
          description: Return a list of players
          content:
            application/json:
              schema:
                type: object
                properties:
                  players:
                    type: array
                    items:
                      type: object
                      properties:
                        id:
                          type: integer
                        name:
                          type: string
                        game_id:
                          type: integer
                        # Add more properties based on your player schema
                  message:
                    type: string
                  user:
                    type: string
      500:
        description: An error occurred while fetching players
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
    """

    try:
        jwt_login_user = get_jwt_identity()       
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM players")
        players = cursor.fetchall()  
        cursor.close()

        if players:
            return jsonify({"players": players,
                            "message":"You are authorized!", 
                            "user":jwt_login_user
                            }), 200
        else:
            return jsonify({"message":'You are authorized! and No players found',
                            "user":jwt_login_user}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)})  


#To check if there are any records record_scores table, to delete
def get_scores():
    """
    Get Scores Function
    ---
    tags:
      - Get Scores
    get:
      summary: Retrieve all scores
      responses:
        200:
          description: Successful retrieval of scores
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Score'
    """
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM record_scores")
    records = cursor.fetchall()  
    cursor.close(); 
    return records

#To fetch scores based on round number
@app.route('/api/fetchscores', methods=['GET'])
@jwt_required()
def fetch_scores_to_edit():
    """
    Fetch Scores Endpoint
    ---
    tags:
      - Fetch Scores
    parameters:
      - in: query
        name: roundNumber
        required: true
        description: Round number to fetch scores
        schema:
          type: integer
    get:
      summary: Retrieve scores based on the round number
      security:
        - JWT: []
      responses:
        200:
          description: Player scores retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                  playerScores:
                    type: array
                    items:
                      type: object
                      properties:
                        name:
                          type: string
                        player_id:
                          type: integer
                        round_number:
                          type: integer
                        score:
                          type: integer
        500:
          description: An error occurred while fetching player scores
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """
    try:
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        round_number= request.args.get('roundNumber')
        # Query to select records from record_scores get scores and join with players to get name based on round_number
        query_template = "SELECT p.name, r.player_id, r.round_number, r.score  FROM record_scores r INNER JOIN players AS p ON p.id = r.player_id WHERE round_number = %s"

        cursor = db.cursor(dictionary=True)
        cursor.execute(query_template, (round_number,))
        playerScores = cursor.fetchall()  
        #print("playerScores :", playerScores)
        cursor.close(); 
        return jsonify({
            "message":'Successful retrieval of the player scores',
            "playerScores": playerScores}), 200
    except Exception as e:
        return jsonify({"error": str(e)})

#To fetch single player scores based on player name
@app.route('/api/playerscores', methods=['GET'])
@jwt_required()
def player_scores_to_edit():

    """
    Player Scores Endpoint
    ---
    tags:
      - Get Player Scores
    get:
      summary: Retrieve scores for a specific player
      security:
        - JWT: []
      parameters:
        - in: query
          name: playerName
          required: true
          description: Name of the player
          schema:
            type: string
      responses:
        200:
          description: Player scores retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                  singlePlayerScores:
                    type: array
                    items:
                      type: object
                      properties:
                        name:
                          type: string
                        player_id:
                          type: integer
                        round_number:
                          type: integer
                        score:
                          type: integer
        500:
          description: An error occurred while fetching player scores
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """
    try:
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        name = request.args.get('playerName')

        #To get player id by player name
        player_id = playerId_ByName(name)

        # Query to select records from record_scores get scores and join with players to get name based on round_number
        query_template = "SELECT p.name, r.player_id, r.round_number, r.score  FROM record_scores r INNER JOIN players AS p ON p.id = r.player_id WHERE r.player_id = %s"

        cursor = db.cursor(dictionary=True)
        cursor.execute(query_template, (player_id,))
        singlePlayerScores = cursor.fetchall()  
        print("singlePlayerScores :", singlePlayerScores)
        cursor.close(); 
        return jsonify({
            "message":'Successful retrieval of player scores',
            "singlePlayerScores": singlePlayerScores}), 200
    except Exception as e:
        return jsonify({"error": str(e)})
    
# get player id by player name
def playerId_ByName(name):
    try:   
        print("Inside playerId_ByName..!")             
        # Query to select records from record_scores get scores and join with players to get name based on round_number
        query = "SELECT id FROM players WHERE name = %s"  # Use parameterized query

        cursor = db.cursor()
        cursor.execute(query, (name,))  # Pass the player's name as a parameter within a tuple
        playerId = cursor.fetchone()

        if playerId is not None:  # Check if playerId is not None before returning
            playerId = playerId[0]
            print("playerId :", playerId)
            cursor.close() 
            return playerId
        else:
            cursor.close()
            return {"error": f"No player found with the name: {name}"}

    except Exception as e:
        return {"error": str(e)}

    
#Clear Scores of a player(s)
@app.route('/api/clearscores', methods=['DELETE'])
@jwt_required
def clear_scores():
    """
    Clear Scores Endpoint
    ---
    tags:
      - Clear Scores
    delete:
      summary: Clear all scores
      security:
        - JWT: []
      responses:
        200:
          description: Scores cleared successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        404:
          description: No records to delete
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        500:
          description: An error occurred
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """
    try:
        records = get_scores()
        if records == 0:
            return jsonify({"message": "There are no records to delete"})
        else:
            cursor = db.cursor()
            cursor.execute("DELETE FROM record_scores")   
            db.commit()
            cursor.close()
            return jsonify({"message": "Previous scores deleted successfully"})
    except Exception as e:
        return {"error": str(e)}
    

#Dynamic fetch based on max round get_roundNumber
@app.route('/api/display_scores_dynamic', methods=['GET'])
@jwt_required()
def get_dynamicScores():

    """
    Retrieve Dynamic Player Scores
    ---
    tags:
      - Display Player Scores
    security:
      - JWT: []
    responses:
      200:
        description: Successfully retrieved player scores
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                playerScores:
                  type: array
                  items:
                    type: object
                    properties:
                      name:
                        type: string
                      total_Score:
                        type: integer
                      # Add properties for dynamic round scores
                      # Example: round_1, round_2, round_3, etc.
                      # You might need to adjust the types based on your data
                      round_1:
                        type: integer
                      round_2:
                        type: integer
                      # ... (add more round properties as needed)
    """
 
    try:            
        jwt_login_user = get_jwt_identity()       
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

        game_name = request.args.get('selectedGame')        
        print(game_name)

        max_round_number = get_max_roundNumber(db)
        print(max_round_number)

        query_template = """
                SELECT
                    p.name,
                    {},
                    SUM(r.score) AS total_Score
                FROM scorerecorder.record_scores r
                INNER JOIN scorerecorder.players AS p ON p.id = r.player_id
                INNER JOIN scorerecorder.games AS g ON g.game_id = p.game_id 
                AND g.game_name = %s
                GROUP BY p.name;
                """
            # Construct the list of conditional aggregate expressions
        conditional_aggregates = [
                    f"SUM(CASE WHEN r.round_number = {round_num} THEN r.score ELSE 0 END) AS round_{round_num}"
                    for round_num in range(1, max_round_number + 1)
                ]
        # Check if conditional_aggregates is empty
        if not conditional_aggregates:
            # Handle the case where there are no conditional aggregates
            query = query_template.format("0 AS no_rounds")  # You can set a default value or an empty aggregate
            return jsonify({
            "message":'There are no player scores / rounds to retrive',
            "playerScores": 0}), 200
        else:
            # Construct the final query by formatting the template
            query = query_template.format(', '.join(conditional_aggregates))

        print(query)

        cursor1 = db.cursor(dictionary=True)
        cursor1.execute(query, (game_name,))
        playerScores = cursor1.fetchall()
        cursor1.close()

        print(playerScores)

        return jsonify({
            "message":'Successful retrieving the players',
            "playerScores": playerScores}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#To get latest roundNumber
@app.route('/api/round-number', methods=['GET'], endpoint='get_round_number')
@jwt_required()
def get_round_number():   
        """
    Get Round Number Endpoint
    ---
    tags:
      - Get Round Number
    get:
      summary: Retrieve the maximum round number
      security:
        - JWT: []
      responses:
        200:
          description: Round number retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  roundNumber:
                    type: integer
                  message:
                    type: string
                  user:
                    type: string
        500:
          description: An error occurred while fetching round number
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
                  message:
                    type: string
    """
        try:
            jwt_login_user = get_jwt_identity() 
            print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
            
            cursor = db.cursor(dictionary=True)
            cursor.execute("SELECT max(round_number) FROM record_scores")
            result = cursor.fetchone()
            # max_round_number = result['max(round_number)'] if result['max(round_number)'] is not None else 0
            cursor.close()

            if result is not None:
                max_round_number = result['max(round_number)']
                if max_round_number is not None:
                    return jsonify({"roundNumber": max_round_number,                                   
                                    "message":"You are authorized! and Data retrieved successfully", 
                                    "user":jwt_login_user
                                }), 200
                else:
                    return jsonify({"message": "You are authorized! and There are no records to display", 
                                    "roundNumber": 0,                                   
                                    "user":jwt_login_user}), 200
            else:
                return jsonify({"message": "There are no records to display", "roundNumber": 0}), 200

        except Exception as e:
            return jsonify({"error": str(e), "message": "An error occurred while fetching roundNumber"}), 500
    
    
#Clear Players and record_scores table in one button click
@app.route('/api/clear-multiple-tables', methods=['DELETE'])
#@jwt_required
def clear_multiple_tables():
    """
    Clear Multiple Tables Endpoint
    ---
    tags:
      - Clear Scores and Players from the System 
    delete:
      summary: Clear records from multiple tables
      security:
        - JWT: []
      responses:
        200:
          description: Records cleared successfully from multiple tables
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        500:
          description: An error occurred while clearing records from tables
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """
    try:
        cursor = db.cursor()
        
        # List of table names to clear
        tables_to_clear = ['record_scores', 'players']

        for table in tables_to_clear:
            delete_query = f"DELETE FROM {table}"
            cursor.execute(delete_query)
        
        db.commit()
        cursor.close()
        
        return jsonify({"message": "Records cleared from multiple tables successfully"})
    except Exception as e:
        return jsonify({"error": str(e)})
    

#Clear Players and record_scores table in one button click
@app.route('/api/clear-players', methods=['DELETE'])
#@jwt_required()
def clear_players():
    """
    Clear Players Endpoint
    ---
    tags:
      - Clear Players from the System 
    delete:
      summary: Clear all player records
      responses:
        200:
          description: Players cleared successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        500:
          description: An error occurred while clearing players
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """
    try:
       
        cursor = db.cursor()
        cursor.execute('DELETE from players')
        db.commit()
        cursor.close()
        
        return jsonify({"message": "Cleared Players Successfully"})
    except Exception as e:
        return jsonify({"error": str(e)})


#To get roles
@app.route('/api/roles', methods=['GET'])
def get_roles():
    """
    Get User Roles Endpoint
    ---
    tags:
      - Available Roles 
    get:
      summary: Retrieve user roles
      responses:
        200:
          description: User roles retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  userRoles:
                    type: array
                    items:
                      type: object
                      properties:
                        role:
                          type: string
        404:
          description: No roles found
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        500:
          description: An error occurred while retrieving roles
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT role FROM roles")
        roles = cursor.fetchall()
        cursor.close()

        print(roles)

        if roles:
            return jsonify({"userRoles": roles}), 200
        else:
            return jsonify({"message": "No roles found"}), 404
        
    except mysql.connector.Error as e:
        error_message = str(e)  # Extract the error message from the exception        
        if "MySQL Connection not available" in error_message:
            return jsonify({"error": "MySQL Connection not available"}), 500
        else:
            return jsonify({"error": "An error occurred"}), 500
        

# Get No of Players who have total_score more than > 75  
@app.route('/api/playersByTotalScore', methods=['GET'])  
@jwt_required()     
def fetchPlayersByTotalScore():
    """
    Fetch Players By Total Score
    ---  
    tags:
      - Players By Total Scores
    security:
      - JWT: []
    responses:
      200:
        description: Successfully fetched player scores
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                playersTotalScore:
                  type: array
                  items:
                    type: object
                    properties:
                      id:
                        type: integer
                      name:
                        type: string
                      game_id:
                        type: integer
                      game_name:
                        type: string
                      total_score:
                        type: integer
    """
    try:
        cursor = db.cursor()

        # SQL query to retrieve players' data based on the sum of scores
        query = """
        SELECT p.id, p.name, p.game_id, g.game_name, SUM(rs.score) as total_score
        FROM players p
        JOIN record_scores rs ON p.id = rs.player_id
        JOIN Games g ON p.game_id = g.gmae_id
        GROUP BY p.id, p.game_id
        HAVING SUM(rs.score) > 75
        """

        cursor.execute(query)
        playersTotalScore = cursor.fetchall()
        cursor.close()

        if playersTotalScore is not None and  len(playersTotalScore) > 0:
            return jsonify({"message": "Total Scores of the Players fetched successfully",
            "playersTotalScore": playersTotalScore}), 200           
        else:
            return jsonify({"message": "There are no records to display", "playersTotalScore": 0}), 200 
        
    except Exception as e:
        return {"error": str(e)}


#Delete duplicate records from Players and record_scores tables
@app.route('/api/delete_duplicates', methods=['DELETE'])
@jwt_required()
def delete_duplicate_records():

    """
    Delete Duplicate Records Endpoint
    ---
    tags:
      - Delete Duplicate Decords
    security:
      - JWT: []
    delete:
      summary: Delete duplicate records of players
      security:
        - JWT: []
      responses:
        200:
          description: Duplicate entries deleted successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        400:
          description: Failed to delete duplicates
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """

    try:
        cursor = db.cursor()

        # Query to delete associated records from the record_scores table for duplicate players in the players table
        delete_query = """
            DELETE r FROM record_scores r
            JOIN (
                SELECT id FROM (
                    SELECT MAX(id) AS id, name
                    FROM players
                    GROUP BY name
                    HAVING COUNT(*) > 1
                ) AS dup_players
            ) AS dup_players ON r.player_id = dup_players.id
        """
        cursor.execute(delete_query)

        # Query to delete the latest record of duplicate players from the players table
        delete_players_query = """
            DELETE p1 FROM players p1
            JOIN (
                SELECT MAX(id) AS id, name
                FROM players
                GROUP BY name
                HAVING COUNT(*) > 1
            ) AS dup_players ON p1.name = dup_players.name AND p1.id = dup_players.id
        """
        cursor.execute(delete_players_query)

        db.commit()
        cursor.close()

        return jsonify({"message": "Duplicate entries deleted successfully."}), 200

    except Exception as e:
        db.rollback()
        cursor.close()
        return jsonify({"Error": str(e)}), 500
    
# To create a game
@app.route('/api/create_game', methods=['POST'])
@jwt_required()
def create_game():
 
    if request.method == 'POST':
        game_name = request.json.get('gameName')  
        game_type = request.json.get('selectedGameType')       

        cursor = db.cursor()

        # Insert a new game into the database
        sql = "INSERT INTO games (game_name, game_type) VALUES (%s, %s)" 
        val=(game_name, game_type)     
        cursor.execute(sql, val)

        db.commit()  # Commit changes to the database
        cursor.close()
        return jsonify({"message": "New Game added successfully"})
    
# To create a game type
@app.route('/api/create_game_type', methods=['POST'])
@jwt_required()
def create_game_type():
 
    if request.method == 'POST':
        game_type = request.json.get('gameType')       

        cursor = db.cursor()

        # Insert a new game into the database
        sql = "INSERT INTO game_type (game_type) VALUES (%s)"       
        cursor.execute(sql, game_type)

        db.commit()  # Commit changes to the database
        cursor.close()
        return jsonify({"message": "Game Type added successfully"})
    
# To get games
@app.route('/api/games', methods=['GET'])
@jwt_required()
def get_games():
        
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
    
        cursor = db.cursor(dictionary=True)           
        cursor.execute( "SELECT game_name, game_id FROM games")
        games = cursor.fetchall()

        db.commit()  # Commit changes to the database
        cursor.close()

        return jsonify({
          "games": games,
          "message": " games retrieved successfully..!",          
          "user":jwt_login_user,
      }), 200

# To get game_types
@app.route('/api/gametypes', methods=['GET'])
@jwt_required()
def get_gametypes():
        
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
    
        cursor = db.cursor(dictionary=True)           
        cursor.execute( "SELECT id, game_type FROM game_type")
        gametypes = cursor.fetchall()

        db.commit()  # Commit changes to the database
        cursor.close()

        return jsonify({
          "gametypes": gametypes,
          "message": " gametypes retrieved successfully..!",          
          "user":jwt_login_user,
      }), 200

# API endpoint to add a Candidate
@app.route('/api/addplayer', methods=['POST'])
@jwt_required()
def add_addplayer():
    
    data = request.get_json()
    #name, age, dateOfBirth, qualification, assetsValue, party, address, district, state, country
    name = data['name']
    mobile = data['mobile']
    game_id = data['selectedGameId']
   

    jwt_login_user = get_jwt_identity() 
    print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

    cursor = db.cursor()
    sql = "INSERT INTO players (name, mobile, game_id) VALUES (%s, %s, %s)"
    val = (name, mobile, game_id)
    cursor.execute(sql, val)
    db.commit()
    cursor.close()

    return jsonify({
                    "message": "Players record inserted successfully", 
                    "user":jwt_login_user,
                    }), 200

# Get existing game details along with players and their scores   
@app.route('/api/player_scores_by_game', methods=['GET'])
@jwt_required()   
def get_player_scores_by_game():
    
    """
    Get player scores by game name
    ---
    tags:
      - Player Scores
    security:
      - JWT: []
    parameters:
      - in: query
        name: gameName
        schema:
          type: string
        required: true
        description: The name of the game to retrieve player scores
    responses:
      200:
        description: Player scores retrieved successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Message confirming successful retrieval
                  example: "Game details retrieved successfully"
                player_scores:
                  type: array
                  description: List of player scores for the specified game
                  items:
                    type: object
                    properties:
                      id:
                        type: integer
                        description: The player's ID
                      name:
                        type: string
                        description: The player's name
                      game_id:
                        type: integer
                        description: The game's ID associated with the player
                      game_name:
                        type: string
                        description: The name of the game
                      total_score:
                        type: integer
                        description: The total score of the player in the game
      401:
        description: Unauthorized - JWT token is missing or invalid
      500:
        description: Internal Server Error - Error occurred during data retrieval
        content:
          application/json:
            schema:
              type: object
              properties:
                Error:
                  type: string
                  description: Error message
    """

    try:
    
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        game_name = request.args.get('selectedGame')
    
        cursor = db.cursor(dictionary=True)
        
        query = """
            SELECT 
                p.id,
                p.name,
                p.game_id,
                g.game_name,
                SUM(rs.score) as total_score
            FROM 
                players p
            JOIN 
                record_scores rs ON p.id = rs.player_id
            JOIN 
                games g ON p.game_id = g.game_id
            WHERE 
                g.game_name = %s
            GROUP BY 
                p.id, p.game_id;
        """

        cursor.execute(query, (game_name,))
        player_scores = cursor.fetchall()
        
        db.commit()
        cursor.close()
        return jsonify({
            "message": "Game details retrieved successfully",
            "player_scores": player_scores,
            }), 200
    
    except Exception as e:
        db.rollback()
        cursor.close()
        return jsonify({"Error": str(e)}), 500

#To get Current Time
@app.route('/api/current-time')
def get_current_time():
    """
    Current Time Endpoint
    ---
    tags:
      - Time
    get:
      summary: Get the current time
      responses:
        200:
          description: Return the current time
          content:
            application/json:
              schema:
                type: object
                properties:
                  current_time:
                    type: string
                    format: date-time
    """
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({"current_time": current_time})

# Example of generating a token with expiration
def generate_token_with_expiration(user_id):
    # Set the expiration time, e.g., 1 hour from now
    expiration = datetime.timedelta(hours=1)    
    # Create a JWT access token with an expiration
    access_token = create_access_token(identity=user_id, expires_delta=expiration)    
    return access_token

@app.route('/api/swagger')  # This endpoint serves your Swagger specification
def generate_swagger_spec():
    # Generate the Swagger specification (JSON or YAML) for your API
    swag = swagger(app)
    swag['info']['title'] = 'Score Recorder'
    swag['info']['version'] = '1.0'
    return jsonify(swag)

# Swagger UI configuration
SWAGGER_URL = '/api/docs'  # URL for Swagger UI
API_URL = '/api/swagger'   # URL to your Swagger JSON or YAML file

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Score Recorder"  # Specify your app name
    }
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Define a route to clear the cache
@app.route('/api/clear-cache')
@jwt_required()
def clear_cache():
    cache.clear()
    return jsonify({"message": 'Cache cleared successfully'})

@app.route('/')
def index():
    return 'Hello, Score Recorder!'

if __name__ == '__main__':
    #app.run()
    #app.run(host='127.0.0.1', port=5001) # Change the port as needed
    app.run(host='0.0.0.0', port=5005) # Change the port as needed
    #app.run(debug=True)