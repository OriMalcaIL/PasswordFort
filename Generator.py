import secrets
import string


def generate_new_password(
        length=32, special_chars: bool = True, digits: bool = True, uppercase: bool = True, lowercase: bool = True
):
    """
    Generates a strong password that fits the specified format.
    :param length: The desired length of the password (int).
    :param special_chars: Whether or not to include special characters in the password (bool).
    :param digits: Whether or not to include digits in the password (bool).
    :param uppercase: Whether or not to include uppercase letters in the password (bool).
    :param lowercase: Whether or not to include lowercase letters in the password (bool).
    :return: The generated password (str).
    """
    characters = ""
    if special_chars:
        characters += string.punctuation
    if digits:
        characters += string.digits
    if uppercase:
        characters += string.ascii_uppercase
    if lowercase:
        characters += string.ascii_lowercase
    if not any([special_chars, digits, uppercase, lowercase]):
        raise ValueError("At least one character type must be selected")
    return "".join(secrets.choice(characters) for i in range(length))


def generate_key(length: int = 32) -> bytes:
    """
    Generate a random key of the given length
    :param length: int - The length of the key to be generated
    :return: bytes - The generated key
    """
    return secrets.token_bytes(length)
