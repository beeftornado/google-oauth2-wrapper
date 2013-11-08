#!/usr/bin/env python

# The MIT License (MIT)

# Copyright (c) 2013 Casey Duquette

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

""" High level utilities to help with basic OAuth functionality.

This is just a wrapper to control the flow, with the heavy lifting 
done by Google Inc.'s oauth2 library (oauth2.py). By controlling the
flow, it can reduce the amount of code you need to write in order to
create access codes multiple times. """

if __name__ == '__main__':
	# Hack to run smoothly in test mode
	import sys
	sys.path.append('../../')

import json
from os import path

from libs.oauth2 import RefreshToken, GenerateOAuth2String, GeneratePermissionUrl, AuthorizeTokens, \
						TestImapAuthentication, GenerateOAuth2String, TestSmtpAuthentication
from helpers.exceptions import OAuthPropertyMissingException, OAuthConfigurationMalformattedException, \
						NotYetImplementedError

__author__ = "Casey Duquette"
__copyright__ = "Copyright 2013"
__credits__ = ["Casey Duquette"]

__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = "Casey Duquette"
__email__ = ""


class OAuthHelper(object):
	""" Helps with OAuth access token generation and refresh token generation.

	See also :mod:`oauth_manager`

	.. code:: python

		# Example usage
		from oauth_helper import OAuthHelper
		...
		oauth_helper = OAuthHelper()
		oauth_helper.json_path = 'oauth2-details.json'
		...
		resp = oauth_helper.first_time_oauth_token()
		print "User's oauth access token is " + resp['access_token']
		print "User's oauth refresh token is " + resp['refresh_token']
		print "The access token expires in " + resp['expires_in'] + " seconds"
		# You will want to save the above
		# When the access_token expires, you need to refresh it with the refresh_token
		...
		oauth_login_argument = oauth_helper.generate_oauth_string('user_email', access_token)

	 """
	def __init__(self, json_path=None):
		super(OAuthHelper, self).__init__()
		self.json_path = json_path

	def json_path():
	    doc = """ The path to the json file with the OAuth settings. The format of this
	    file is assumed to be the format of the generated json file from the web-application
	    console found here: https://cloud.google.com/console """
	    def fget(self):
	        return self._json_path
	    def fset(self, value):
	        self._json_path = value
	        if value is not None:
		        self._load_json()	# auto-load json if path changes
	    def fdel(self):
	        del self._json_path
	    return locals()
	json_path = property(**json_path())

	@property
	def scope(self):
		return getattr(self, '_scope', 'https://mail.google.com/')
	@scope.setter
	def scope(self, value):
		self._scope = value

	@property
	def user_email(self):
		return self._user_email
	@user_email.setter
	def user_email(self, value):
		self._user_email = value

	def _load_json(self):
		""" If a json file is provided with the oauth settings to use, then this will populate the 
		properties with those settings """
		
		# Assertion checks, but not with assertions
		if getattr(self, 'json_path', None) is None:
			raise OAuthPropertyMissingException("No json file was specified; Can't populate fields from json.")
		
		if not path.exists(self.json_path):
			raise OAuthPropertyMissingException("Json file supplied, but missing on the file system. Trying to use: {0}".format(self.json_path))
		
		with open(self.json_path) as data:
			json_data = json.load(data)
		
		if not json_data or not len(json_data):
			raise OAuthPropertyMissingException("Json file supplied, exists, but seems empty. File is: {0}".format(self.json_path))
		
		if 'oauth' not in json_data:
			raise OAuthConfigurationMalformattedException("Json file is incomplete or improperly formatted; it is missing a 'oauth' property")
		
		if 'installed' not in json_data['oauth']:
			raise OAuthConfigurationMalformattedException("Json file is incomplete or improperly formatted; it is missing a 'installed' property")
		
		web_properties = ['auth_uri', 'client_secret', 'token_uri', 'client_email', 'client_x509_cert_url', 'client_id', 'auth_provider_x509_cert_url']
		for web_p in web_properties:
			if web_p not in json_data['oauth']['installed']:
				raise OAuthConfigurationMalformattedException("Json file is incomplete or improperly formatted; it is missing a '{0}' property".format(web_p))
			setattr(self, web_p, json_data['oauth']['installed'][web_p])

		assert self.client_secret is not None, "Client secret cannot be empty."
		assert self.client_id is not None, "Client id cannot be empty."

	def first_time_oauth_token(self, interactive=True):
		""" If this is a new user, for whom you do not yet have an access token or refresh token,
		then this is the right method. It will generate one, of course after getting authorized. 

		.. note::

			This will only work if your app in the Google console is setup as "native"

		Args:
	    	
	    Kwargs:
	    	interactive (bool):  Should this go back and forth wth user over stdin to get token.

	    Returns:
	    	dict.  With keys::

	    		refresh_token -- boop
	    		access_token -- boop
	    		expires_in -- Seconds untill the access token expires.

	    Raises:
	    	NotYetImplementedError
		"""
		assert self.client_secret is not None, "Client secret cannot be empty."
		assert self.client_id is not None, "Client id cannot be empty."
		assert self.scope is not None, "Scope cannot be empty."

		if not interactive:
			raise NotYetImplementedError("Interactive mode is the only way to go")

		print 'To authorize token, visit this url and follow the directions:'
		print '  %s' % GeneratePermissionUrl(self.client_id, self.scope)
		authorization_code = raw_input('Enter verification code: ')
		response = AuthorizeTokens(self.client_id, self.client_secret,
			authorization_code)
		print 'Refresh Token: %s' % response['refresh_token']
		print 'Access Token: %s' % response['access_token']
		print 'Access Token Expiration Seconds: %s' % response['expires_in']

		return response

	def generate_oauth_string(self, interactive=True, user_email=None, access_token=None, base64_encode=True):
		""" Creates the argument to supply to OAuth based authentications.

		Args:
	    	user_email (str):  The user's email address you want to generate the oauth login argument for.
	    	access_token (str):  The user's access token that has already been authorized and everything.

	    Kwargs:
	    	interactive (bool):  Should this go back and forth wth user over stdin to get token.

	    Returns:
	    	str.  OAuth login argument

	    Raises:
	    	NotYetImplementedError
		"""
		assert user_email is not None, "User email cannot be empty."
		assert access_token is not None, "Access token cannot be empty."

		if not interactive:
			raise NotYetImplementedError("Interactive mode is the only way to go")

		oauth = GenerateOAuth2String(user_email, access_token, base64_encode=base64_encode)
		# print ('OAuth2 argument:\n' + oauth)

		return oauth

	def refresh_token(self, interactive=True, refresh_token=None):
		""" Refreshes the access token.

		:param interactive: Should this go back and forth with user over stdin to get token
		:type interactive: bool
		:default interactive: True
		:param refresh_token: The refresh token for the user that was returned during the 
						original authorization process.
		:type refresh_token: str or unicode

		:returns: dict with two keys: access_token, expires_in
		"""
		assert refresh_token is not None, "Refresh_token cannot be empty."
		assert self.client_id is not None, "Client id cannot be empty."
		assert self.client_secret is not None, "Client secret cannot be empty."

		if not interactive:
			raise NotYetImplementedError("Interactive mode is the only way to go")

		response = RefreshToken(self.client_id, self.client_secret,
			refresh_token)
		# print 'Access Token: %s' % response['access_token']
		# print 'Access Token Expiration Seconds: %s' % response['expires_in']

		return response

	def test_access_token(self, user_email=None, auth_string=None, access_token=None):
		""" Tests the access token to see if it can successfully be used to authenticate 
		against the user's account.

		.. note::
			You can provide either the already generated authentication string or the 
			access token for the user, both are NOT required. If both are supplied, the
			auth_string will take precedence.

		:param user_email: The user's email address you want to test authentication against.
		:param auth_string: The authentication string to use to login (should be equivalent
						to :func:`generate_oauth_string`)
		:param access_token: The access token for the user. Will be converted into an auth
						string.
		:returns: True if the auth worked, False otherwise
		"""
		if auth_string is None:
			auth_string = self.generate_oauth_string(user_email=user_email, access_token=access_token, base64_encode=False)
		TestImapAuthentication(user_email, auth_string)
		return True

if __name__ == '__main__':
	print "Testing oauth creation"
	oauth_helper = OAuthHelper()
	oauth_helper.json_path = '../../oauth2-details.sjson'
	resp = oauth_helper.first_time_oauth_token()
	email = raw_input("What is your full email address to test the login: ")
	oauth_helper.test_access_token(email, access_token=resp['access_token'])