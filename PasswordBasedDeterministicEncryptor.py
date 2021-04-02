from typing import Optional

from Crypto.Cipher import DES
from Crypto.Hash import MD5

"""
This encryptor is going to to replicate the Java jasypt encryptor by using the PBEWithMD5AndDES algorithm
"""


class PasswordBasedDeterministicEncryptor:
    __default_iterations = 1000
    __encoding = 'utf-8'

    def __init__(self, password: str, salt: str):
        self.__password_bytes = password.encode(self.__encoding)
        self.__salt_bytes = salt.encode(self.__encoding)

    def encrypt(self, text: Optional[str]) -> Optional[str]:
        if text is None:
            return None
        else:
            text_to_encrypt = text
            padding = 8 - len(text_to_encrypt) % 8
            text_to_encrypt += chr(padding) * padding
            encrypted_value_bytes = self.__create_encryptor().encrypt(text_to_encrypt.encode(self.__encoding))
            return encrypted_value_bytes.hex().upper()

    def decrypt(self, encrypted_text: Optional[str]) -> Optional[str]:
        if encrypted_text is None:
            return None
        else:
            bytes_to_decrypt = bytes.fromhex(encrypted_text)
            decrypted_text_bytes = self.__create_encryptor().decrypt(bytes_to_decrypt)
            trimmed_decrypted_text_bytes = decrypted_text_bytes.rstrip(b'\2,\1,\3,\4,\5,\6,\7,\0')
            decrypted_value = trimmed_decrypted_text_bytes.decode(self.__encoding)
            # backspace would be appended at the end when the length of the original value is multiply by 8
            return decrypted_value.replace('\b', '')

    def __create_encryptor(self):
        hasher = MD5.new()
        hasher.update(self.__password_bytes)
        hasher.update(self.__salt_bytes[:8])
        result = hasher.digest()

        for i in range(1, self.__default_iterations):
            hasher = MD5.new()
            hasher.update(result)
            result = hasher.digest()
        return DES.new(result[:8], DES.MODE_CBC, result[8:16])
