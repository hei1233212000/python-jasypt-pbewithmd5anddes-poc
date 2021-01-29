from PasswordBasedDeterministicEncryptor import PasswordBasedDeterministicEncryptor

"""
As the encryptor is using the block cipher, the encrypted value would be always the same with the same source 
"""
if __name__ == '__main__':
    salt = 'thisisasalt'
    password = 'thisisapassword'
    original_value = 'any value'
    expected_encrypted_value = '65E4F5F9DDC8B3232596727971151664'

    encryptor = PasswordBasedDeterministicEncryptor(password, salt)

    print('original_value: {}'.format(original_value))
    encrypted_value = encryptor.encrypt(original_value)
    print('encrypted_value: {}'.format(encrypted_value))
    print('expected_encrypted_value: {}'.format(expected_encrypted_value))
    assert encrypted_value == expected_encrypted_value

    decrypted_value = encryptor.decrypt(encrypted_value)
    print('decrypted_value: {}'.format(decrypted_value))
    assert decrypted_value == original_value

    another_text = 'whatever things'
    first_encrypted_value = encryptor.encrypt(another_text)
    second_encrypted_value = encryptor.encrypt(another_text)
    assert first_encrypted_value == second_encrypted_value
    assert encryptor.decrypt(first_encrypted_value) == another_text
    assert encryptor.decrypt(second_encrypted_value) == another_text
