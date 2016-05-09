from mockito import Mock, when, verify
import tabletest

import secrets.config
import secrets


class SecretsTest(tabletest.TableTestCase):
    def test_gen_user_secret(self):
        """Generation of a user secret which randomly salts and hashes."""

        secret_hasher = Mock()
        secret_hasher.digest_size = 3 
        when(secret_hasher).hexdigest().thenReturn('ababa')

        secret_generator = secrets.SecretGenerator(lambda: secret_hasher, lambda x: 'aaa')

        self.assertEqual(secret_generator.gen_user_secret(1), u'ababa')
        verify(secret_hasher).update(u'aaa#1')

    def test_gen_for_two_users(self):
        """Generation of a user secret from two user ids."""

        secret_hasher = Mock()
        secret_hasher.digest_size = 3 

        secret_generator = secrets.SecretGenerator(lambda: secret_hasher, lambda x: 'aaa')

        when(secret_hasher).hexdigest().thenReturn('ababa')
        self.assertEqual(secret_generator.gen_user_secret(1), u'ababa')
        verify(secret_hasher).update(u'aaa#1')

        when(secret_hasher).hexdigest().thenReturn('bcax')
        self.assertEqual(secret_generator.gen_user_secret(2), u'bcax')
        verify(secret_hasher).update(u'aaa#2')

    def test_standard_generator_proper_size_output(self):
        """The (real) standard generator has a string output of proper size."""

        secret_generator = secrets.SecretGenerator()

        user_secret = secret_generator.gen_user_secret(1)
        self.assertIsInstance(user_secret, str)
        self.assertEqual(len(user_secret), secrets.config.USER_SECRET_SIZE)

    def test_standard_generator_three_calls(self):
        """Three calls with three different user ids produce different results."""

        secret_generator = secrets.SecretGenerator()

        user_secret_1 = secret_generator.gen_user_secret(1)
        user_secret_2 = secret_generator.gen_user_secret(2)
        user_secret_3 = secret_generator.gen_user_secret(3)
        self.assertNotEqual(user_secret_1, user_secret_2)
        self.assertNotEqual(user_secret_1, user_secret_3)
        self.assertNotEqual(user_secret_2, user_secret_3)

    def test_standard_generator_three_calls_same_ids(self):
        """Three calls with the same user id produce different results."""

        secret_generator = secrets.SecretGenerator()

        user_secret_1 = secret_generator.gen_user_secret(1)
        user_secret_2 = secret_generator.gen_user_secret(1)
        user_secret_3 = secret_generator.gen_user_secret(1)
        self.assertNotEqual(user_secret_1, user_secret_2)
        self.assertNotEqual(user_secret_1, user_secret_3)
        self.assertNotEqual(user_secret_2, user_secret_3)

    def test_standard_generator_three_calls_differnt_ids_same_random(self):
        """Three calls with different user ids produce different results even with bad generator."""

        secret_generator = secrets.SecretGenerator(gen_random_bytes=lambda x: 'aa')

        user_secret_1 = secret_generator.gen_user_secret(1)
        user_secret_2 = secret_generator.gen_user_secret(2)
        user_secret_3 = secret_generator.gen_user_secret(3)
        self.assertNotEqual(user_secret_1, user_secret_2)
        self.assertNotEqual(user_secret_1, user_secret_3)
        self.assertNotEqual(user_secret_2, user_secret_3)


    _IS_PASSWORD_ALLOWED_TEST_CASES = [
        ('12345', True),
        ('', False),
        ('1', False),
        ('12', False),
        ('123', False),
        ('1234', True),
        ('1' * 1024, True),
        ('1' * 1025, False)
    ]

    @tabletest.tabletest(_IS_PASSWORD_ALLOWED_TEST_CASES)
    def test_is_password_allowed(self, test_case):
        """Various valid and invalid passwords are recognized as such."""
        generator = secrets.SecretGenerator()
        self.assertEqual(generator.is_password_allowed(test_case[0]), test_case[1])


    def test_hash_password_and_gen_salt(self):
        """Hashing of a password."""

        crypt = Mock()

        secret_generator = secrets.SecretGenerator(crypt=crypt)

        when(crypt).gensalt().thenReturn('aaaa')
        when(crypt).hashpw('1234', 'aaaa').thenReturn('bbbb')

        self.assertEqual(secret_generator.hash_password_and_gen_salt(u'1234'), 'bbbb')

    def test_hash_for_two_users(self):
        """Generation of a password from two users."""

        crypt = Mock()

        secret_generator = secrets.SecretGenerator(crypt=crypt)

        when(crypt).gensalt().thenReturn('aaaa')
        when(crypt).hashpw('1234', 'aaaa').thenReturn('bbbb')

        self.assertEqual(secret_generator.hash_password_and_gen_salt(u'1234'), 'bbbb')

        when(crypt).gensalt().thenReturn('AAAA')
        when(crypt).hashpw('hello', 'AAAA').thenReturn('BBBB')

        self.assertEqual(secret_generator.hash_password_and_gen_salt(u'hello'), 'BBBB')

    def test_standard_hash_has_proper_size_output(self):
        """The (real) standard generator has a string output of proper size."""

        secret_generator = secrets.SecretGenerator()

        hidden_password = secret_generator.hash_password_and_gen_salt(u'hello')
        self.assertIsInstance(hidden_password, str)
        self.assertEqual(len(hidden_password), secrets.config.HIDDEN_PASSWORD_SIZE)

    def test_standard_generator_three_calls(self):
        """Three calls with three different passwords produce different results."""

        secret_generator = secrets.SecretGenerator()

        hidden_password_1 = secret_generator.hash_password_and_gen_salt(u'1234')
        hidden_password_2 = secret_generator.hash_password_and_gen_salt(u'hello')
        hidden_password_3 = secret_generator.hash_password_and_gen_salt(u'kitty')
        self.assertNotEqual(hidden_password_1, hidden_password_2)
        self.assertNotEqual(hidden_password_1, hidden_password_3)
        self.assertNotEqual(hidden_password_2, hidden_password_3)

    def test_standard_generator_three_calls_same_ids(self):
        """Three calls with the same password produce different results."""

        secret_generator = secrets.SecretGenerator()

        hidden_password_1 = secret_generator.hash_password_and_gen_salt(u'1234')
        hidden_password_2 = secret_generator.hash_password_and_gen_salt(u'1234')
        hidden_password_3 = secret_generator.hash_password_and_gen_salt(u'1234')
        self.assertNotEqual(hidden_password_1, hidden_password_2)
        self.assertNotEqual(hidden_password_1, hidden_password_3)
        self.assertNotEqual(hidden_password_2, hidden_password_3)


    _CHECK_PASSWORD_TEST_CASES = [
        (u'1234', u'1234', True),
        (u'1234', u'hello', False),
        (u'1234', u'kitty', False)
        ]

    @tabletest.tabletest(_CHECK_PASSWORD_TEST_CASES)
    def test_check_password(self, test_case):
        """Check password works as intended."""

        secret_generator = secrets.SecretGenerator()
        hidden_password = secret_generator.hash_password_and_gen_salt(test_case[0])
        self.assertEqual(
            secret_generator.check_password(test_case[1], hidden_password), test_case[2])


if __name__ == '__main__':
    unittest.main()
