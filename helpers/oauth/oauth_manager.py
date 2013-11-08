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

""" Manages the user oauth tokens for you.

This goes one level higher than the :mod:`oauth_helper` by taking care of the management. It will
track access tokens and refresh tokens for users and refresh the access tokens as needed for you.
It will handle all storage and retrieval work for you. The only task it can't do for you is the 
actual authorization on behalf of a user :)

.. note::
	This was never meant to scale to infinity. I only needed something to handle more than one,
	but less than ten user accounts. I believe this implementation can scale up to 100 safely 
	without a significant impact to performance, but after that I would not rely on this, and 
	instead suck it up and start using a database. """

if __name__ == '__main__':
	# Hack to run smoothly in test mode
	import sys
	sys.path.append('../../')

import datetime
import cPickle as pickle
from os import path

from helpers.exceptions import NotYetImplementedError, MissingArgumentError, UserDoesNotExistError
from oauth_helper import OAuthHelper

__author__ = "Casey Duquette"
__copyright__ = "Copyright 2013"
__credits__ = ["Casey Duquette"]

__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = "Casey Duquette"
__email__ = ""


class OAuthUser(object):
	""" A user of the oauth system """
	def __init__(self, login=None, access_token=None, refresh_token=None, expires_in=None):
		super(OAuthUser, self).__init__()
		self.login = login
		self.access_token = access_token
		self.refresh_token = refresh_token
		self.expires_in = expires_in

	# Making 'email' synonomous with 'login'
	@property
	def login(self):
		return getattr(self, 'email', None)
	@login.setter
	def login(self, value):
		setattr(self, 'email', value)
		

class OAuthManager(object):
	""" Manages OAuth tokens for users and allows an application to get setup with OAuth as painless as possible.

	.. code:: python

		# Example usage
		print "Testing oauth manager"
		oauth_manager = OAuthManager()
		oauth_helper = oauth_manager.oauth_helper
		oauth_manager.json_path = '../../oauth2-details.sjson'
		oauth_manager.offline_store_path = '../../oauth2-creds.data'
		print "User store count is " + str(len(oauth_manager.store))
		email = raw_input("What is your full email address: ")
		resp = oauth_helper.first_time_oauth_token()
		oauth_helper.test_access_token(email, access_token=resp['access_token'])
		oauth_manager.set_access_token(email, resp['access_token'], resp['refresh_token'], resp['expires_in'])
		print "User store count is " + str(len(oauth_manager.store))
		...
		# To get a current oauth login string that is refreshed for you and can be used for imap login
		oauth_manager.oauth_login_string('email')

	 """
	def __init__(self):
		super(OAuthManager, self).__init__()
		self.oauth_helper = OAuthHelper()
		self.store = dict()

	@property
	def json_path(self):
		return self.oauth_helper.json_path
	@json_path.setter
	def json_path(self, value):
		self.oauth_helper.json_path = value

	@property
	def offline_store_path(self):
		return getattr(self, '_offline_store_path', None)

	@offline_store_path.setter
	def offline_store_path(self, value):
		setattr(self, '_offline_store_path', value)
		if len(self.store):
			# already have users in store, assume they should be saved
			self.save()
		else:
			# no users yet, try and load
			self.load()

	@property
	def offline_encrypted(self):
		return getattr(self, 'offline_encrypted', False)

	@offline_encrypted.setter
	def offline_encrypted(self, value):
		if value != False:
			raise NotYetImplementedError()
		setattr(self, 'offline_encrypted', value)

	def get_access_token(self, email):
		""" Returns a valid, non-expired access token or None if the user doesn't exist. """
		if email is None:
			raise MissingArgumentError()
		if email not in self.store:
			raise UserDoesNotExistError()
		self.validate_access_token(email)
		return self.store.get(email).access_token

	def set_access_token(self, email, access_token, refresh_token, expires_in):
		if None in [email, access_token, refresh_token, expires_in]:
			raise MissingArgumentError()
		user = self.store[email] if email in self.store else OAuthUser()
		for p in ['email', 'access_token', 'refresh_token', 'expires_in']:
			setattr(user, p, locals()[p])
		user.expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=user.expires_in)
		self.store[email] = user
		self.save()

	def validate_access_token(self, email):
		if email is None:
			raise MissingArgumentError()
		if email not in self.store:
			raise UserDoesNotExistError()
		user = self.store[email]
		if datetime.datetime.utcnow() >= user.expires_at:
			# need to refresh access token
			self.refresh_access_token(email)

	def refresh_access_token(self, email):
		if email is None:
			raise MissingArgumentError()
		if email not in self.store:
			raise UserDoesNotExistError()
		user = self.store[email]
		response = self.oauth_helper.refresh_token(refresh_token=user.refresh_token)
		self.set_access_token(email, response['access_token'], user.refresh_token, response['expires_in'])

	def oauth_login_string(self, email, base64_encode=True):
		"""
		.. note::
			If using imaplib, you must pass base64_encode=False
		"""
		if email is None:
			raise MissingArgumentError()
		if email not in self.store:
			raise UserDoesNotExistError()
		return self.oauth_helper.generate_oauth_string(user_email=email, access_token=self.get_access_token(email), base64_encode=base64_encode)

	def save(self):
		if self.offline_store_path:
			pickle.dump( self.store, open( self.offline_store_path, "wb" ) )

	def load(self):
		if self.offline_store_path and path.exists(self.offline_store_path):
			self.store = pickle.load( open( self.offline_store_path, "rb" ) )
			for user in self.store.values():
				print "Loaded " + user.email

	def get_users(self):
		return self.store.values()

if __name__ == '__main__':
	print "Testing oauth manager"
	oauth_manager = OAuthManager()
	oauth_helper = oauth_manager.oauth_helper
	oauth_manager.json_path = '../../oauth2-details.sjson'
	oauth_manager.offline_store_path = '../../oauth2-creds.data'
	print "User store count is " + str(len(oauth_manager.store))
	email = raw_input("What is your full email address: ")
	resp = oauth_helper.first_time_oauth_token()
	oauth_helper.test_access_token(email, access_token=resp['access_token'])
	oauth_manager.set_access_token(email, resp['access_token'], resp['refresh_token'], resp['expires_in'])
	print "User store count is " + str(len(oauth_manager.store))
	