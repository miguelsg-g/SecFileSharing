import unittest
from . import utils
from . import models
class TestEncryptionMethods(unittest.TestCase):
    def test_rsa_key_pair_generation(self):
        public_key, private_key = utils.generate_rsa_key_pair()
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(private_key)
    def setUp(self):
        # Creamos un usuario de prueba
        super().setUp()
        self.user = models.AppUser.objects.create(username='testuser', email='testuser@example.com')
        self.user.public_key, private_key = utils.generate_rsa_key_pair()
        return self.user, private_key
    def test_encrypt_decrypt_symmetric_key(self):
        # Importamos un usuario de la base de datos
        user, private_key = self.setUp()
        symmetric_key = utils.generate_symmetric_key()
        encrypted_key = utils.encrypt_symmetric_key(user.public_key, symmetric_key)
        decrypted_key = utils.decrypt_symmetric_key(private_key, encrypted_key)
        self.assertEqual(symmetric_key, decrypted_key)