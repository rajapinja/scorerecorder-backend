from flask import current_app
import datetime
import jwt


def get_jwt_secret_key():
    # Access the JWT secret key directly from the Flask app instance
    #with current_app.app_context():
        jwt_secret_key = current_app.config['JWT_SECRET_KEY']
        if jwt_secret_key:
            return jwt_secret_key
        else:
            raise Exception("JWT_SECRET_KEY not found in the app configuration")

# Usage example:
jwt_secret_key = get_jwt_secret_key()
print(jwt_secret_key)

# Example of generating a token with expiration
def generate_token_with_expiration(user_id):
    #expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expires in 1 day
    # Calculate the expiration time as 1 hour from the current time
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=4)
    # Now 'expiration' holds the datetime for 1 hour from the current time
    payload = {'user_id': user_id, 'exp': expiration}
    token = jwt.encode(payload, jwt_secret_key, algorithm='HS256')
    return token