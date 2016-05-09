"""A module which provides the common crypto operations for the app."""

import bcrypt
import hashlib
import os

from .config import MIN_PASSWORD_SIZE
from .config import MAX_PASSWORD_SIZE


class SecretGenerator(object):
    """A generator of user secrets, passwords etc.

    Useful when adopting an IoC setup for applications. Fake generators can be provided for the
    purpose of unittesting and mocking libraries can be used for fine grained control.
    """

    def __init__(self, secret_hasher_factory=hashlib.sha256, gen_random_bytes=os.urandom, crypt=bcrypt):
        """Construct a secret generator.

        Arguments:
          secret_hasher_factory: a constructor of hasher. Must implement the interface defined in
            hashlib.
          gen_random_bytes (function(n) -> string[n]): a function which generates a string of random
            bytes of size n, when invoked with n.
          crypt: an object which follows the interface of the bcrypt module.
        """
        self._secret_hasher_factory = secret_hasher_factory
        self._gen_random_bytes = gen_random_bytes
        self._crypt = crypt

    def gen_user_secret(self, user_id):
        """Generate an unique id which is externally usable.

        The unique id is an ASCII string, of size given by USER_SECRET_SIZE.

        The string will be derived from user_id. However the derivation process is non-repeatable,
        so calling the function twice with the same argument will produce different results.

        Otherwise the id will have all the usual cryptographic properties.

        The id will be sent to external systems (the clients), and therfore, were it simply user_id,
        third parties would become aware of system interals such as the number of users, ranges of
        valid values etc.

        Arguments:
          user_id (int): the base from which the unique id is derived.

        Returns:
          The external id, as a string.
        """
        assert isinstance(user_id, int)

        secret_hasher = self._secret_hasher_factory()
        salt = self._gen_random_bytes(secret_hasher.digest_size)
        secret_hasher.update('{}#{}'.format(salt, str(user_id)))
        return secret_hasher.hexdigest()

    def is_password_allowed(self, password):
        """Tests whether a password satisfies some minimum hardness requirements.

        Arguments:
          password(basestring): the password to test.

        Returns:
          Whether the password satisfies the minimum hardness requirements or not.
        """
        return len(password) >= MIN_PASSWORD_SIZE and len(password) <= MAX_PASSWORD_SIZE

    def hash_password_and_gen_salt(self, password):
        """Generate a salt and hash the password with it according to application rules.

        Return both the salt and hashed password as a singel string of size HASHED_PASSWORD_SIZE.

        Arguments:
          password (basestring): The password to be hashed. It must be a string which is valid
          according to is_password_allowed.

        Return:
          The string representation of the salt and password.
        """
        assert isinstance(password, basestring)
        assert self.is_password_allowed(password)

        return self._crypt.hashpw(password.encode('utf-8'), self._crypt.gensalt())

    def check_password(self, test_password, hidden_password):
        """Check whether a given password is the same as a hashed password.

        Arguments:
          test_password (basestring): the password to test.
          hidden_password (basestring): a password, as processed by hash_password_and_gen_salt.

        Return:
          Whether hash(test_password) == hidden_password.
        """
        assert isinstance(test_password, basestring)
        assert isinstance(hidden_password, basestring)

        return self._crypt.hashpw(
            test_password.encode('utf-8'), hidden_password.encode('utf-8')) == hidden_password
