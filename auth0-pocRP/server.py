"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

import constants

import base64
import requests
import http.client
from verifier import verify

from flask import request
from auth0.v3.authentication.token_verifier import TokenVerifier, AsymmetricSignatureVerifier

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

#AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
#AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
#AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
#AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)

AUTH0_BASE_URL = 'https://pocprado.us.auth0.com'
AUTH0_CLIENT_ID = 'xJVZP8AVqcZKRjDowj7ik3Qico4k6HMk'
AUTH0_CLIENT_SECRET = 'b8aJNVTytm_tQSKDXvxlME19kUQ470zLqhpCDAhFHBt3Q4CqsicySf5NCASPgvRH'
AUTH0_CALLBACK_URL = 'https://pocpy.herokuapp.com/callback'
AUTH0_DOMAIN = 'pocprado.us.auth0.com'
AUTH0_AUDIENCE = 'https://pocprado.us.auth0.com/api/v2/'
SECRET_KEY = 'ZwqFHeUqrcA4KNZuCvp9QTvhJ6AOrcnd_kDN1a8ORSU5K8_OIr_wCTgIVyRbAASt'


app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True


@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/calc/<value1>/<value2>')
def calc(value1, value2):
  
    conn = http.client.HTTPSConnection("pocprado.us.auth0.com")
    payload = "{\"client_id\":\"lv14yZZStAL5yNByLWF8z06sPFBYtCyq\",\"client_secret\":\"U6x3UN1t1y-lXvmhx0S5HHWo54_6D57_EPIVqd4SGrvoC3adoZBL5ySWn4tNERX_\",\"audience\":\"https://pocpy.herokuapp.com/calc\",\"grant_type\":\"client_credentials\"}"

    headers = { 'content-type': "application/json" }
    conn.request("POST", "/oauth/token", payload, headers)
    res = conn.getresponse()
    data = res.read()
    id_token = eval(data.decode("utf-8"))["access_token"]
  
    jwks_url = 'https://{}/calc/.well-known/jwks.json'.format(constants.AUTH0_DOMAIN)
  
    verify(id_token, jwks_url)

    result = int(value1) + int(value2)
    
    return str(result)
    

@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 3000))
