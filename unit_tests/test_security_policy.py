from pure_backend.core.security import password_is_valid


def test_password_requires_letters_and_numbers():
    assert password_is_valid("abcdefgh") is False
    assert password_is_valid("12345678") is False
    assert password_is_valid("abc12345") is True
