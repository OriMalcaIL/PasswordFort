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
        iv = self.create_iv()
        cipher = self.create_cipher(iv)
        cipher_password = cipher.encrypt(self._pad(password))
        return base64.b64encode(iv + cipher_password)

    def create_cipher(self, iv: bytes) -> AES:
        """
        Create and return a new AES cipher object with the given IV
        :param iv: bytes - the initialization vector to be used with the cipher
        :return: an AES cipher object
        """
        # Create a new AES cipher object with the key, mode and IV
        return AES.new(self.key, AES.MODE_CBC, iv)

    @staticmethod
    def create_iv() -> bytes:
        return get_random_bytes(AES.block_size)

    @staticmethod
    def _pad(data: str) -> bytes:
        """
        Pad the data to a multiple of AES block size
        :param data: str - The data to be padded
        :return: bytes - The padded data
        """
        # Calculate the number of padding bytes needed
        padding_size = AES.block_size - (len(data) % AES.block_size)
        # Create a byte string containing the padding bytes
        padding = bytes([padding_size]) * padding_size
        # Returns the input data encoded to bytes with the padding bytes
        return data.encode() + padding
