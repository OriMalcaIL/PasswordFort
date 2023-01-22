import secrets
import string


def generate_new_password(
    length=32,
    special_chars: bool = True,
    digits: bool = True,
    uppercase: bool = True,
    lowercase: bool = True,
):
    """
    creates a generated new password with flexible complexity
    :return: a random generated password
    """
    choices = {
        "special_chars": string.punctuation,
        "digits": string.digits,
        "uppercase": string.ascii_uppercase,
        "lowercase": string.ascii_lowercase,
    }
    chosen_chars = "".join(choices.get(key, "") for key in choices if locals()[key])
    return "".join(secrets.choice(chosen_chars) for i in range(length))


def generate_key(length: int = 32) -> bytes:
    """
    Generate a random key of the given length
    """
    return secrets.token_bytes(length)
