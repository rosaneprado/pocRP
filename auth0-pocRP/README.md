# Auth0 Python Web App PoC

This PoC demonstrates how to add authentication to a Python web app using Auth0.

Running the App

Make sure you have python and pip installed.

Rename .env.example to .env and populate it with the client ID, domain, secret, callback URL and audience for your Auth0 app. Add the callback URL to the settings section of your Auth0 client.

Register http://localhost:3000/callback as Allowed Callback URLs and http://localhost:3000 as Allowed Logout URLs in your client settings.

Run pip install -r requirements.txt to install the dependencies and run python server.py. The app will be served at http://localhost:3000/.

What is Auth0?

- Implement authentication with multiple identity providers, including social (e.g., Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc), or enterprise (e.g., Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc.)
- Log in users with username/password databases, passwordless, or multi-factor authentication
- Link multiple user accounts together
- Generate signed JSON Web Tokens to authorize your API calls and flow the user identity securely
- Access demographics and analytics detailing how, when, and where users are logging in
- Enrich user profiles from other data sources using customizable JavaScript rules
