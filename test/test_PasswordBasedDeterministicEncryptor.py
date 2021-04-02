import string
import random

from PasswordBasedDeterministicEncryptor import PasswordBasedDeterministicEncryptor


def test_encrypt():
    original_value = 'any value'
    expected_encrypted_value = '65E4F5F9DDC8B3232596727971151664'
    encryptor = create_encryptor()
    encrypted_value = encryptor.encrypt(original_value)
    assert encrypted_value == expected_encrypted_value


def test_decrypt():
    encrypted_value = '65E4F5F9DDC8B3232596727971151664'
    expected_decrypted_value = 'any value'
    encryptor = create_encryptor()
    decrypted_value = encryptor.decrypt(encrypted_value)
    assert decrypted_value == expected_decrypted_value


def test_encrypt_and_then_decrypt():
    for str_len in range(1, 100):
        original_value = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(1, str_len + 1))
        encryptor = create_encryptor()
        encrypted_value = encryptor.encrypt(original_value)
        decrypted_value = encryptor.decrypt(encrypted_value)
        if decrypted_value != original_value:
            raise AssertionError(
                'decrypted_value[{}] does not equal to the original_value[{}]'.format(decrypted_value, original_value))


def create_encryptor():
    salt = 'thisisasalt'
    password = 'thisisapassword'
    return PasswordBasedDeterministicEncryptor(password, salt)
