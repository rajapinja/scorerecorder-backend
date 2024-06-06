from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import secrets
import mysql.connector
import bcrypt
import MySQLdb
import datetime
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin, logout_user
from user_roles import user_roles
from user_roles import insert_users_roles, user_already_exists, get_user_id, get_users_roles_role_id, get_role
from max_roundnumber import get_max_roundNumber
import datetime
#from db import query_db

app = Flask(__name__)
CORS(app)

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
    host="localhost",
    user="root",
    password="password",
    database="13cardsgame"
)

# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'password'
# app.config['MYSQL_DB'] = '13cardsgame'

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
        return user
    except MySQLdb.Error as e:
         return jsonify({'error': handle_mysql_error(e)})
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
            db.commit()
            cursor.close()
            #Call users_roles table to update with user roles from users_roles module
            sucess = insert_users_roles(db, user, role)
            if sucess:              
                return jsonify({'message': 'Registration successful with '+sucess}), 200
            else:
                return jsonify({'error': 'Registration Failed with User and Role'}), 200   

    except MySQLdb.Error as e:
        error_code = e.errno  # Get the MySQL error code
        if error_code == 409:
            error_message = "Duplicate entry. User already exists."
        else:
            error_message = "An error occurred during registration."
        return jsonify({"error": error_message}), 400
    except mysql.connector.IntegrityError as e:
        error_code = e.errno  # Get the MySQL error code
        if error_code == 1062:
            error_message = "Duplicate entry. User already exists."
        else:
            error_message = "An error occurred during registration."

        return jsonify({"error": error_message}), 400

    
@app.errorhandler(MySQLdb.Error)
def handle_mysql_error(e):
    return jsonify({'error': 'MySQL Error: ' + str(e)})

@app.route('/api/userlogin', methods=['POST'])
def userlogin():
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
                    print("access_token : ",access_token)

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
                          
    except MySQLdb.Error as e:
         return jsonify({'error': handle_mysql_error(e)})
    except mysql.connector.IntegrityError as e:
        error_message = str(e)  # Extract the error message from the exception
        print(error_message)
        return jsonify({'error': error_message})

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
    data = request.get_json()
    name = data['name']
    mobile = data['mobile']

    jwt_login_user = get_jwt_identity() 
    print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

    #Check if game is in progress, check max round number, if it round number#1 , add player with initial score of 25, for each round
    message = insert_player_record(name, mobile)

    # cursor = db.cursor()
    # sql = "INSERT INTO players (name, mobile) VALUES (%s, %s)"
    # val = (name, mobile)
    # cursor.execute(sql, val)
    # db.commit()
    # cursor.close()
    return jsonify({
                    "message": message,
                    "user":jwt_login_user,
                    })

# API endpoint to add scores for a player, on each round
@app.route('/api/record_score', methods=['POST'])
@jwt_required()
def record_scores():

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
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM record_scores")
    records = cursor.fetchall()  
    cursor.close(); 
    return records

#To fetch scores based on round number
@app.route('/api/fetchscores', methods=['GET'])
@jwt_required()
def fetch_scores_to_edit():
    try:
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        round_number= request.args.get('roundNumber')
        # Query to select records from record_scores get scores and join with players to get name based on round_number
        query_template = f"SELECT p.name, r.player_id, r.round_number, r.score  FROM record_scores r INNER JOIN players AS p ON p.id = r.player_id WHERE round_number = {round_number}"

        cursor = db.cursor(dictionary=True)
        cursor.execute(query_template)
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
    try:
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        name = request.args.get('playerName')

        #To get player id by player name
        player_id = playerId_ByName(name)

        # Query to select records from record_scores get scores and join with players to get name based on round_number
        query_template = f"SELECT p.name, r.player_id, r.round_number, r.score  FROM record_scores r INNER JOIN players AS p ON p.id = r.player_id WHERE r.player_id = {player_id}"

        cursor = db.cursor(dictionary=True)
        cursor.execute(query_template)
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
@login_required
def clear_scores():
    records = get_scores()
    if records == 0:
        return jsonify({"message": "There are no records to delete"})
    else:
        cursor = db.cursor()
        cursor.execute("DELETE FROM record_scores")   
        db.commit()
        cursor.close()
        return jsonify({"message": "Previous scores deleted successfully"})

#Dynamic fetch based on max round get_roundNumber
@app.route('/api/display_scores_dynamic', methods=['GET'])
@jwt_required()
def get_dynamicScores():
 
    try:            
        jwt_login_user = get_jwt_identity()       
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

        max_round_number = get_max_roundNumber(db)

        query_template = """
                SELECT
                    p.name,
                    {},
                    SUM(r.score) AS total_Score
                FROM 13cardsgame.record_scores r
                INNER JOIN 13cardsgame.players AS p ON p.id = r.player_id
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

        #print(query)

        cursor1 = db.cursor(dictionary=True)
        cursor1.execute(query)
        playerScores = cursor1.fetchall()
        cursor1.close()
        #print(playerScores)
        return jsonify({
            "message":'Successful retrieving the players',
            "playerScores": playerScores}), 200
    
    except MySQLdb.Error as e:
         return jsonify({'error': handle_mysql_error(e)})   

#To get latest roundNumber
@app.route('/api/round-number', methods=['GET'], endpoint='get_round_number')
@jwt_required()
def get_round_number():   
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
#@login_required
def clear_multiple_tables():
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
#@login_required
def clear_players():
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

#If Play is in progress, additional player can join by using this function
def insert_player_record(player_name, mobile_number):
    try:
        cursor = db.cursor()

        # Check if the record_scores table is empty
        cursor.execute("SELECT COUNT(*) FROM record_scores")
        record_count = cursor.fetchone()[0]

        # Check for Max Game ID from games table 
        cursor.execute("SELECT MAX(game_id) FROM games")
        game_id = cursor.fetchone()[0]

        # Inserting record into players table
        insert_player_query = "INSERT INTO players (name, mobile, game_id) VALUES (%s, %s)"
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
    
#Delete duplicate records from Players and record_scores tables
@app.route('/api/delete_duplicates', methods=['DELETE'])
@jwt_required()
def delete_duplicate_records():
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
    
# Create a cursor object

@app.route('/api/create_game', methods=['POST'])
@jwt_required()
def create_game():
    if request.method == 'POST':
        game_name = request.json.get('gameName')

        cursor = db.cursor()

        # Insert a new game into the database
        sql = "INSERT INTO Games (game_name) VALUES (%s)"
        val = (game_name,)
        cursor.execute(sql, val)

        db.commit()  # Commit changes to the database
        cursor.close()
        return jsonify({"message": "Game added successfully"})

# Get existing game details along with players and their scores   
@app.route('/api/player_scores_by_game', methods=['GET'])
@jwt_required()   
def get_player_scores_by_game():
    try:
    
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        game_name = request.args.get('gameName')
    
        cursor = db.cursor(dictionary=True)
        
        query = """
            SELECT 
                p.id,
                p.name,
                p.game_id,
                g.game_name,
                SUM(rs.score) as total_score
            FROM 
                Players p
            JOIN 
                Record_Scores rs ON p.id = rs.player_id
            JOIN 
                Games g ON p.game_id = g.game_id
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
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({"current_time": current_time})

# Example of generating a token with expiration
def generate_token_with_expiration(user_id):
    # Set the expiration time, e.g., 1 hour from now
    expiration = datetime.timedelta(hours=1)    
    # Create a JWT access token with an expiration
    access_token = create_access_token(identity=user_id, expires_delta=expiration)    
    return access_token

if __name__ == '__main__':
    #app.run()
    app.run(host='127.0.0.1', port=5001) # Change the port as needed
    #app.run(debug=True)
