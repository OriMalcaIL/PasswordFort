"""
Written By Ori Malca ameleh
Reviewed By roe a homo
"""
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Encryption:
    def __int__(self, key: bytes) -> None:
        self.key = key

    def encrypt_password(self, password) -> bytes:
        init_vector = self.create_init_vector()

        cipher = self.create_cipher(init_vector)
        cipher_password = cipher.encrypt(self._pad(password))

        return base64.b64encode(init_vector + cipher_password)

    def create_cipher(self, init_vector: bytes) -> AES:
        """
        Create and return a new AES cipher object with the given IV
        :param init_vector: bytes - the initialization vector to be used with the cipher
        :return: an AES cipher object
        """
        return AES.new(self.key, AES.MODE_CBC, init_vector)

    @staticmethod
    def create_init_vector() -> bytes:
        return get_random_bytes(AES.block_size)

    @staticmethod
    def _pad(data: str) -> bytes:
        """
        Filling the string with a padding
        :param data: str - The data to be padded
        :return: bytes that contain the data and the padding
        """
        # Calculate the number of padding bytes needed
        padding_size = AES.block_size - (len(data) % AES.block_size)
        # Create a byte string containing the padding bytes
        padding = bytes([padding_size]) * padding_size
        # Returns the input data encoded to bytes with the padding bytes
        return data.encode() + padding
