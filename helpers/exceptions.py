#!/usr/bin/env python

""" Project defined exceptions """

class NotYetImplementedError(Exception):
	""" This functionality is not yet implemented """
	pass

class OAuthPropertyMissingException(Exception):
	""" Not interesting. Thrown if something OAuth related is attemped,
	but there is not enough information to start the request. """
	pass

class OAuthConfigurationMalformattedException(Exception):
	""" Thrown when a piece of information used during the OAuth process
	is not properly formatted, or missing keys, or values. """
	pass

class MissingArgumentError(Exception):
	""" If you're missing function arguments """
	pass

class UserDoesNotExistError(Exception):
	pass

class InsecureNotSupportedError(Exception):
	pass