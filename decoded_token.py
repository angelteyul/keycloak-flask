from flask import Flask, redirect, url_for, session, request, render_template
from dotenv import load_dotenv
import requests
import logging
import jwt
import os

app = Flask(__name__)
app.secret_key = '123456'

load_dotenv()

logging.basicConfig(level=logging.DEBUG)

# keycloak data settings
keycloak_server_url = os.getenv('KEYCLOAK_SERVER_URL')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')

realm_name = os.getenv('REALM_NAME')
realm_rsa_public_key = f"""-----BEGIN PUBLIC KEY-----
{os.getenv('REALM_PUBLIC_KEY')}
-----END PUBLIC KEY-----"""


@app.route('/')
def index():
    if 'user' in session:
        roles = session.get('roles', [])
        return render_template('home.html', username=session['user']['username'], email=session['user']['email'], roles=roles)
    else:
        return redirect(url_for('login'))


@app.route('/login')
def login():
    authorize_url = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/auth"
    redirect_uri = 'http://127.0.0.1:5000/callback'
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid profile email'
    }

    return redirect(f"{authorize_url}?{'&'.join([f'{key}={value}' for key, value in params.items()])}")


@app.route('/callback')
def callback():
    code = request.args.get('code')
    logging.debug(f"Callback received with code: {code}")

    token_endpoint = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/token"

    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': 'http://127.0.0.1:5000/callback',
        'client_id': client_id,
        'client_secret': client_secret
    }

    try:
        response = requests.post(token_endpoint, data=payload)
        token_data = response.json()

        if 'access_token' in token_data:
            userinfo_endpoint = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/userinfo"
            userinfo_response = requests.get(userinfo_endpoint, headers={'Authorization': f"Bearer {token_data['access_token']}"})            
            userinfo = userinfo_response.json()

            # decode token and get roles
            decoded = decode_token(token_data['access_token'])
            roles = []

            if decoded is not None:
                roles = get_roles_from_token(decoded)
                session['roles'] = roles
                logging.debug(roles)

            session['user'] = {
                'id_token': token_data.get('id_token'),
                'access_token': token_data.get('access_token'),
                'refresh_token': token_data.get('refresh_token'),
                'username': userinfo.get('preferred_username'),
                'email': userinfo.get('email')
            }

            logging.debug("User logged in successfully.")
            return redirect(url_for('index'))
        else:
            logging.error("Failed to fetch tokens.")
            return "Failed to fetch tokens."

    except Exception as e:
        logging.error(f"Exception during token exchange: {e}")
        return "Failed to fetch tokens."


@app.route('/logout')
def logout():
    logging.debug('Attempting to logout...')

    try:
        logout_endpoint = f"{keycloak_server_url}/realms/{realm_name}/protocol/openid-connect/logout"
        redirect_uri = 'http://127.0.0.1:5000/login'

        id_token = session.get('id_token')

        response = requests.get(f"{logout_endpoint}?id_token_hint={id_token}&post_logout_redirect_uri={redirect_uri}", timeout=5)

        session.clear()
        logging.debug('Session cleared. Redirecting to login...')

        return redirect(url_for('login'))

    except requests.exceptions.RequestException as e:
        logging.error(f"Exception during logout: {e}")
        return "Failed to logout. Please try again."


# role based access to route
@app.route('/admin')
def admin():
    if 'user' in session and 'role_admin' in session['roles']:
        return render_template('admin.html')
    else:
        return 'Access denied, you are not administrator.', 403


# decode jwt token
def decode_token(token):
    try:
        decoded = jwt.decode(token, realm_rsa_public_key, algorithms=['RS256'], audience='account')
        logging.debug(decoded)
        return decoded
    except jwt.ExpiredSignatureError:
        logging.debug('Expired Signature')
        return None
    except jwt.InvalidTokenError:
        logging.debug('Invalid Token')
        return None


# get roles from token
def get_roles_from_token(decoded_token):
    return decoded_token.get('realm_access', {}).get('roles', [])


if __name__ == '__main__':
    app.run(debug=True)
