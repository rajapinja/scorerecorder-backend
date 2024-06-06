
import mysql.connector
from flask import Blueprint, jsonify

user_roles = Blueprint('Blueprint', __name__)

@user_roles.errorhandler(mysql.connector.Error)
def handle_mysql_error(e):
    return jsonify({'error': 'MySQL Error: ' + str(e)})

#To Update users_roles table
def insert_users_roles(db, user, role):
    print('inside insert_users_roles')
    try:
        
        #Call users_roles table to update with user roles
        user_id = get_user_id(db, user)
        print(user_id)
        role_id = get_role_id(db, role)
        print(role_id)

        cursor = db.cursor()
        sql = 'INSERT INTO users_roles (user_id, role_id) VALUES (%s, %s)'
        val = (user_id, role_id)
        cursor.execute(sql, val)  

        success = "users_roles successful"          
        return success
    
    except mysql.connector.Error as e:
         return jsonify({'error': handle_mysql_error(e)})    
    finally:
         db.commit()
         #cursor.close() 

#To get user id from users table
def get_user_id(db,user):
    print('inside get_user_id')
    try:
        cursor = db.cursor()          
        cursor.execute('select id from users where username=%s', (user,))
        # Fetch the result
        result = cursor.fetchone()

        user_id = result[0]
        return user_id
    
    except mysql.connector.Error as e:
         return jsonify({'error': handle_mysql_error(e)})    
    finally:
         db.commit()
         #cursor.close() 


#To get role is from roles table
def get_role_id(db, role):
    print('inside get_user_role')
    try:
        cursor = db.cursor()
        cursor.execute('select id from roles where role=%s', (role,))
         # Fetch the result
        result = cursor.fetchone()

        role_id = result[0]
        return role_id    
        
    except mysql.connector.Error as e:
         return jsonify({'error': handle_mysql_error(e)})   
    finally:
         db.commit() 

#To for existing user
def user_already_exists(db, user):

    print('inside user_already_exists')
    try:        

        cursor = db.cursor()              
        cursor.execute('SELECT COUNT(*) FROM users where username=%s', (user,))  
        result = cursor.fetchone()  
        userCount = result[0]

        if userCount == 0:
            return False
        else:
            return True   
    except mysql.connector.Error as e:
         return jsonify({'error': handle_mysql_error(e)})    
    finally:
         db.commit()
        #cursor.close() 

#To get role from roles table by passing 
def get_role_id(db, role):
    print('inside get_user_role')
    try:
        cursor = db.cursor()
        cursor.execute('select id from roles where role=%s', (role,))
         # Fetch the result
        result = cursor.fetchone()

        role_id = result[0]
        return role_id    
        
    except mysql.connector.Error as e:
         return jsonify({'error': handle_mysql_error(e)})   
    finally:
         db.commit()

#Login logic
#To get role is from users_roles table
def get_users_roles_role_id(db, user_id):
    print('inside get_users_roles_role_id')
    try:
        cursor = db.cursor()
        cursor.execute('select role_id from users_roles where user_id=%s', (user_id,))
         # Fetch the result
        result = cursor.fetchone()

        role_id = result[0]
        return role_id    
        
    except mysql.connector.Error as e:
         return jsonify({'error': handle_mysql_error(e)})   
    finally:
         db.commit()

#To get role from roles table
def get_role(db, role_id):
    print('inside get_role')
    try:
        cursor = db.cursor()
        cursor.execute('select role from roles where id=%s', (role_id,))
         # Fetch the result
        result = cursor.fetchone()

        role= result[0]
        return role   
        
    except mysql.connector.Error as e:
         return jsonify({'error': handle_mysql_error(e)})   
    finally:
         db.commit()    


      
      