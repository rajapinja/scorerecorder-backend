
from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin, logout_user
from flask_cors import CORS
import secrets
import mysql.connector
import bcrypt
import MySQLdb

#Static Check
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()       
    username = data['username']
    password = data['password']   

    if username in users and users[username]['password'] == password:
        user = User(username)
        login_user(user)
        return jsonify({'message': 'Login successful'})

    return jsonify({'message': 'Invalid credentials'}), 401

#Get scores to display 
@app.route('/api/display_scores', methods=['GET'])
@login_required
def get_scores():

    query = """
    SELECT
        p.name,
        SUM(CASE WHEN r.round_number = 1 THEN r.score ELSE 0 END) AS round_1,
        SUM(CASE WHEN r.round_number = 2 THEN r.score ELSE 0 END) AS round_2,
        SUM(CASE WHEN r.round_number = 3 THEN r.score ELSE 0 END) AS round_3,
        SUM(CASE WHEN r.round_number = 4 THEN r.score ELSE 0 END) AS round_4,
        SUM(CASE WHEN r.round_number = 5 THEN r.score ELSE 0 END) AS round_5,
        SUM(CASE WHEN r.round_number = 6 THEN r.score ELSE 0 END) AS round_6,
        SUM(CASE WHEN r.round_number = 7 THEN r.score ELSE 0 END) AS round_7,
        SUM(r.score) AS total_Score
    FROM 13cardsgame.record_scores r
    INNER JOIN 13cardsgame.players AS p ON p.id = r.player_id
    GROUP BY p.name;
    """

    cursor = db.cursor(dictionary=True)
    cursor.execute(query)
    playerScores = cursor.fetchall()
    #db.close() 
    cursor.close()   
    return jsonify({"playerScores": playerScores})