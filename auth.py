from flask import Flask, redirect, url_for, session, request, render_template, abort
from keycloak import KeycloakOpenID
from dotenv import load_dotenv
from functools import wraps
import requests, logging, jwt, os,uuid

# config flask and utils
app = Flask(__name__)
app.secret_key = '1234567890'

load_dotenv()

logging.basicConfig(level=logging.DEBUG)


# configure client
keycloak_openid = KeycloakOpenID(
    server_url=os.getenv('KEYCLOAK_SERVER_URL'),
    client_id=os.getenv('CLIENT_ID'),
    realm_name=os.getenv('REALM_NAME'),
    client_secret_key=os.getenv('CLIENT_SECRET_KEY'),
    verify=False
)

# get all keycloak endpoints
config_well_known = keycloak_openid.well_known()

# define roles
role_admin = os.getenv('ROLE_ADMIN')  # os.getenv('ROLE_ADMIN').split(',')
role_basic = os.getenv('ROLE_BASIC')

# validate roles required for routes
def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('login'))

            user_roles = session['user']['roles']

            if any(role in user_roles for role in required_roles):
                return f(*args, **kwargs)
            else:
                return abort(403)
        return decorated_function
    return decorator


@app.route('/')
def index():
    if 'user' in session:
        data = {
            'username': session['user']['username'],
            'email': session['user']['email'],
            'roles': session['user']['roles']
        }

        return render_template('home.html', **data)
    else:
        return redirect(url_for('login'))


@app.route('/login')
def login():
    auth_url = keycloak_openid.auth_url(
        redirect_uri='http://127.0.0.1:5000/callback',
        scope='openid profile email',
        state=str(uuid.uuid4())
    )

    return(redirect(auth_url))


@app.route('/callback')
def callback():
    code = request.args.get('code')

    if not code:
        return 'Error: No code received.', 400
    
    try:
        access_token = keycloak_openid.token(
            grant_type='authorization_code',
            code=code,
            redirect_uri='http://127.0.0.1:5000/callback'
        )
        
        if 'access_token' in access_token:
            userinfo = keycloak_openid.userinfo(access_token['access_token'])
            token_info = keycloak_openid.introspect(access_token['access_token'])
            roles = token_info.get('realm_access', {}).get('roles', [])

            session['user'] = {
                'id_token': access_token.get('id_token'),
                'access_token': access_token.get('access_token'),
                'refresh_token': access_token.get('refresh_token'),
                'username': userinfo.get('preferred_username'),
                'email': userinfo.get('email'),
                'roles': roles
            }

            logging.debug("User logged in successfully.")
            return redirect(url_for('index'))
        else:
            logging.error("Failed to fetch tokens.")
            return "Failed to fetch tokens as there's no access token found."

    except Exception as e:
        logging.error(f"Exception during login: {e}")
        return "Failed to login as an exception occurred. Please try again."


@app.route('/logout')
def logout():
    logging.debug('Attempting to logout...')

    try:
        keycloak_openid.logout(session['user']['refresh_token'])

        session.clear()
        logging.debug('Session cleared. Redirecting to login...')

        return redirect(url_for('login'))

    except requests.exceptions.RequestException as e:
        logging.error(f"Exception during logout: {e}")
        return "Failed to logout. Please try again."


# role based access to route
@app.route('/admin')
@role_required([role_admin])
def admin():
    return render_template('admin.html')


if __name__ == '__main__':
    app.run(debug=True)
