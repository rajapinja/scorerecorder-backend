from flask import current_app, g
import mysql.connector

def get_db():
    if 'db' not in g:       
        g.db = mysql.connector.connect(
            host=current_app.config['MYSQL_HOST'],
            user=current_app.config['MYSQL_USER'],
            password=current_app.config['MYSQL_PASSWORD'],
            db=current_app.config['MYSQL_DB']
        )
    return g.db

def query_db(query, args=(), one=False):
    db = get_db()
    cursor = db.connection.cursor()
    cursor.execute(query, args)
    rv = cursor.fetchall()
    cursor.close()
    return (rv[0] if rv else None) if one else rv