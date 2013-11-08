google-oauth2-wrapper
=====================

Python wrapper around Google's OAuth2 client for easy integration

### Please Explain

I needed something to simply the OAuth process I was using to connect to Google. I was using their oauth2.py library from their site and had great utilities in it, but it became cumbersome to do some trivial things.

It isn't meant to be a comprehensive solution to simplifying the process for everyone; it just fit my needs. Although it won't fit everyone's needs, I thought it could help enough people to make it worth open sourcing.

I'm sorry there isn't a lot of docs or examples for this, but it really just targets a niche of projects so there wouldn't be much.

### Features

* Maintains user->access token mappings (very basic to get you up and running, stored in plaintext, not secure)
* Automatically refreshes the access tokens if they expire (Google's typically expire in a day)
* Includes a simple way to auth new users and get their access token (has some limitations)

### Basic Usage

```python
from helpers.oauth import OAuthManager

# Create the manager for users and their access tokens and managing refreshes
oauth_manager = OAuthManager()

# Configure the manager with the path to our client id and client secret and load any users with tokens
oauth_manager.json_path = OAUTH_PROPERTIES_JSON_PATH
oauth_manager.offline_store_path = CREDENTIAL_STORE_JSON_PATH

print "User store count is " + str(len(oauth_manager.store))

# The command line version of auth'ing a user
email = raw_input("What is your full email address: ")
resp = oauth_helper.first_time_oauth_token()

# If you want to verify the token works
oauth_helper.test_access_token(email, access_token=resp['access_token'])

# Add the user to the manager for storage and 'managing'
oauth_manager.set_access_token(email, resp['access_token'], resp['refresh_token'], resp['expires_in'])

# Verify user was added
print "User store count is " + str(len(oauth_manager.store))

# To get a current oauth login string that is refreshed for you and can be used for imap login
oauth_manager.oauth_login_string('email', base64_encode=False)
```
