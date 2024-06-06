from flask import current_app
import datetime
import jwt
from functools import wraps


def get_jwt_secret_key():
    # Access the JWT secret key directly from the Flask app instance
   # with current_app.app_context():
        jwt_secret_key = current_app.config.get('JWT_SECRET_KEY')
        if jwt_secret_key:
            return jwt_secret_key
        else:
            raise Exception("JWT_SECRET_KEY not found in the app configuration")

# Usage example:
jwt_secret_key = get_jwt_secret_key()


# Example of generating a JWT token
def generate_token(user_id):
    payload = {'user_id': user_id}
    token = jwt.encode(payload, jwt_secret_key, algorithm='HS256')
    return token

# Example of generating a token with expiration
def generate_token_with_expiration(user_id):
    #expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expires in 1 day
    # Calculate the expiration time as 1 hour from the current time
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    # Now 'expiration' holds the datetime for 1 hour from the current time
    payload = {'user_id': user_id, 'exp': expiration}
    token = jwt.encode(payload, jwt_secret_key, algorithm='HS256')
    return token

# Example of generating a token with user roles and permissions
def generate_token_with_roles(user_id, roles, permissions):
    payload = {'user_id': user_id, 'roles': roles, 'permissions': permissions}
    token = jwt.encode(payload, jwt_secret_key, algorithm='HS256')
    return token

# Example of validating a token
def validate_token(token):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        user_id = payload['user_id']
        return user_id
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.DecodeError:
        return None  # Invalid token
    
# Example of generating a new token based on a refresh token
def refresh_token(refresh_token):
    try:
        payload = jwt.decode(refresh_token, app.secret_key, algorithms=['HS256'])
        user_id = payload['user_id']
        new_token = generate_token_with_expiration(user_id)
        return new_token
    except jwt.ExpiredSignatureError:
        return None  # Refresh token has expired
    except jwt.DecodeError:
        return None  # Invalid refresh token

#Token Verification and Authorization:
def verify_and_authorize(token, required_permissions):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        user_roles = payload.get('roles', [])
        user_permissions = payload.get('permissions', [])

        # Check if the user has any of the required permissions
        if any(permission in user_permissions for permission in required_permissions):
            return payload['user_id']
        else:
            return None  # User doesn't have the required permissions
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.DecodeError:
        return None  # Invalid token

    
#Protect Routes Based on Permissions:
@app.route('/admin', methods=['GET'])
def admin_route():
    token = request.headers.get('Authorization')  # Extract token from headers
    user_id = verify_and_authorize(token, ['admin_permission'])
    if user_id is not None:
        return jsonify({'message': 'Admin content'}), 200
    else:
        return jsonify({'error': 'Access denied'}), 403


@app.route('/protected', methods=['GET'])
def protected_route():
    token = request.headers.get('Authorization')  # Extract token from headers
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        user_id = payload['user_id']
        # Perform actions for authenticated user
        return jsonify({'message': f'Protected content for user {user_id}'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.DecodeError:
        return jsonify({'error': 'Invalid token'}), 401

# In your JWT-related module
def generate_token(user_id, roles):
    # Retrieve permissions based on user's roles from the database
    permissions = get_permissions_for_roles(roles)
    
    payload = {'user_id': user_id, 'roles': roles, 'permissions': permissions}
    token = jwt.encode(payload, jwt_secret_key, algorithm='HS256')
    return token

# ... other code ...
def get_permissions_for_roles(roles):
    permissions = []

    try:
       
        cursor = db.cursor()

        for role_name in roles:
            cursor.execute(
                'SELECT p.name FROM permissions p '
                'INNER JOIN role_permissions rp ON p.id = rp.permission_id '
                'INNER JOIN roles r ON rp.role_id = r.id '
                'WHERE r.name = %s', (role_name,))
            role_permissions = cursor.fetchall()
            permissions.extend(permission[0] for permission in role_permissions)

    except MySQLdb.Error as e:
        print("Error fetching permissions:", e)
    finally:
        cursor.close()
        db.close()

    return permissions


# In your app.py file
@app.route('/admin', methods=['GET'])
def admin_route():
    token = request.headers.get('Authorization')  # Extract token from headers
    user_id = verify_and_authorize(token, ['edit_data', 'manage_users'])
    
    if user_id is not None:
        return jsonify({'message': 'Admin content'}), 200
    else:
        return jsonify({'error': 'Access denied'}), 403  


# Define endpoint-permission mapping
ENDPOINT_PERMISSIONS = {
    '/admin': ['edit_data', 'manage_users'],
    '/manager': ['approve_requests']
    # Add more endpoints and their required permissions
}


# Custom decorator to check permissions
def requires_permission(required_permissions):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')  # Extract token from headers
            user_id = verify_and_authorize(token, required_permissions)
            
            if user_id is not None:
                return view_func(*args, **kwargs)
            else:
                return jsonify({'error': 'Access denied'}), 403
        return wrapper
    return decorator

#Apply the Decorator to Protected Routes:

@app.route('/admin', methods=['GET'])
@requires_permission(['edit_data', 'manage_users'])
def admin_route():
    return jsonify({'message': 'Admin content'}), 200

@app.route('/manager', methods=['GET'])
@requires_permission(['approve_requests'])
def manager_route():
    return jsonify({'message': 'Manager content'}), 200
