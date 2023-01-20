import base64
from Crypto.Cipher import AES


class Decryption:
    """
    A class to handle AES decryption with an IV
    """

    def __init__(self, key: bytes):
        """
        Initialize the class with a key
        :param key: bytes - The key to be used for decryption
        """
        self.key = key

    def decrypt_password(self, data: bytes) -> str:
        """
        Decrypt the given data using AES
        :param data: bytes - The data to be decrypted
        :return: str - The decrypted data
        """
        # Decode the base64 encoded data
        password = base64.b64decode(data)
        # Extract the IV from the decoded data
        iv = self.extract_iv(password)
        # Extract the ciphertext from the decoded data
        ciphertext = password[AES.block_size:]
        # Create a new AES cipher object with the key and IV
        cipher = self.create_cipher(iv)
        # Decrypt the ciphertext
        decrypted_password = self._unpad(cipher.decrypt(ciphertext))
        # Decode the plaintext from bytes to string
        return decrypted_password.decode()

    def create_cipher(self, iv: bytes) -> AES:
        """
        Create and return a new AES cipher object with the given IV
        :param iv: bytes - the initialization vector to be used with the cipher
        :return: an AES cipher object
        """
        # Create a new AES cipher object with the key, mode and IV
        return AES.new(self.key, AES.MODE_CBC, iv)

    @staticmethod
    def extract_iv(password: bytes) -> bytes:
        return password[: AES.block_size]

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """
        Remove the padding from the data
        :param data: bytes - The data to be unpadded
        :return: bytes - The unpadded data
        """
        padding_size = data[-1]
        return data[:-padding_size]
