import base64
from Crypto.Cipher import AES


class Decryption:
    """
    A fitting decryption for the encryption module
    """
    def __init__(self, key: bytes):
        self.key = key

    def decrypt_password(self, data: bytes) -> str:
        """
        Decrypt the given data using AES
        :param data: bytes - The data that needs to be decrypted
        :return: str - The decrypted data
        """
        password = base64.b64decode(data)
        init_vector = self.extract_iv(password)
        ciphertext = password[AES.block_size:]
        cipher = self.create_cipher(init_vector)
        decrypted_password = self._unpad(cipher.decrypt(ciphertext))
        return decrypted_password.decode()

    def create_cipher(self, init_vector: bytes) -> AES:
        """
        Create and return a new AES cipher object with the given IV
        :param init_vector: bytes - the initialization vector to be used with the cipher
        :return: an AES cipher object
        """
        # Create a new AES cipher object with the key, mode and IV
        return AES.new(self.key, AES.MODE_CBC, init_vector)

    @staticmethod
    def extract_iv(data: bytes) -> bytes:
        """
        extract the IV from the given data
        :return: the IV Used
        """
        return data[: AES.block_size]

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """
        Remove the padding from the data
        """
        padding_size = data[-1]
        return data[:-padding_size]
