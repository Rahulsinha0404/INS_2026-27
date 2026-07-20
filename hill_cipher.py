"""
Hill Cipher Encryption and Decryption
=====================================

The Hill cipher encrypts a block of letters by multiplying its numeric vector
by a square key matrix modulo 26. Letters map as A=0, B=1, ..., Z=25.

For decryption, the key matrix must have an inverse modulo 26. Therefore its
determinant must be relatively prime to 26 (gcd(determinant, 26) == 1).

This implementation uses row vectors:
    encrypted_block = plaintext_block * key_matrix (mod 26)

Example 2 x 2 key matrix:
    [[3, 2],
     [3, 5]]
With this key, HELP encrypts to HIAT.
"""

import math
import string


MODULUS = 26
ALPHABET = string.ascii_uppercase


def normalize(text: str) -> str:
    """Keep English letters only and convert them to uppercase."""
    return "".join(character for character in text.upper() if character in ALPHABET)


def validate_key(key: list[list[int]]) -> None:
    """Ensure the key is a non-empty square matrix invertible modulo 26."""
    if not key or not all(isinstance(row, list) for row in key):
        raise ValueError("Key must be a non-empty list of rows.")

    size = len(key)
    if any(len(row) != size for row in key):
        raise ValueError("Key matrix must be square (same number of rows and columns).")

    determinant = determinant_of(key)
    if math.gcd(determinant, MODULUS) != 1:
        raise ValueError(
            f"Key is not invertible modulo 26: determinant is {determinant}. "
            "Choose a key whose determinant has no common factor with 26."
        )


def determinant_of(matrix: list[list[int]]) -> int:
    """Return the integer determinant using recursive cofactor expansion."""
    size = len(matrix)
    if size == 1:
        return matrix[0][0]
    if size == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

    return sum(
        (-1) ** column
        * matrix[0][column]
        * determinant_of(minor(matrix, 0, column))
        for column in range(size)
    )


def minor(matrix: list[list[int]], remove_row: int, remove_column: int) -> list[list[int]]:
    """Return the submatrix after removing one row and one column."""
    return [
        [value for column, value in enumerate(row) if column != remove_column]
        for row_index, row in enumerate(matrix)
        if row_index != remove_row
    ]


def modular_inverse(value: int, modulus: int = MODULUS) -> int:
    """Return x such that value*x is 1 modulo modulus."""
    value %= modulus
    for candidate in range(1, modulus):
        if (value * candidate) % modulus == 1:
            return candidate
    raise ValueError(f"{value} has no inverse modulo {modulus}.")


def inverse_key(key: list[list[int]]) -> list[list[int]]:
    """Calculate the inverse of an integer key matrix modulo 26.

    inverse(A) = inverse(det(A)) * adjugate(A)  (mod 26)
    """
    validate_key(key)
    size = len(key)
    determinant = determinant_of(key)
    determinant_inverse = modular_inverse(determinant)

    # The cofactor matrix, transposed, is the adjugate matrix.
    adjugate = [
        [(-1) ** (row + column) * determinant_of(minor(key, column, row))
         for column in range(size)]
        for row in range(size)
    ]
    return [
        [(determinant_inverse * value) % MODULUS for value in row]
        for row in adjugate
    ]


def multiply_block(block: list[int], key: list[list[int]]) -> list[int]:
    """Multiply a row-vector block by a matrix, modulo 26."""
    size = len(key)
    return [
        sum(block[row] * key[row][column] for row in range(size)) % MODULUS
        for column in range(size)
    ]


def transform(text: str, key: list[list[int]]) -> str:
    """Apply a validated key matrix to normalized text, padding with X if needed."""
    validate_key(key)
    size = len(key)
    clean_text = normalize(text)
    clean_text += "X" * ((-len(clean_text)) % size)

    result = []
    for start in range(0, len(clean_text), size):
        block = [ord(letter) - ord("A") for letter in clean_text[start:start + size]]
        result.extend(ALPHABET[value] for value in multiply_block(block, key))
    return "".join(result)


def encrypt(plaintext: str, key: list[list[int]]) -> str:
    """Encrypt plaintext. X is added to complete an incomplete final block."""
    return transform(plaintext, key)


def decrypt(ciphertext: str, key: list[list[int]]) -> str:
    """Decrypt ciphertext using the modular inverse of the key matrix.

    A trailing X may be padding, but is retained because it could be genuine.
    """
    clean_text = normalize(ciphertext)
    if len(clean_text) % len(key) != 0:
        raise ValueError("Ciphertext length must be a multiple of the key size.")
    return transform(clean_text, inverse_key(key))


if __name__ == "__main__":
    # Standard 2 x 2 example. Determinant = 9, and gcd(9, 26) = 1.
    key = [[3, 2], [3, 5]]
    plaintext = "HELP"

    ciphertext = encrypt(plaintext, key)
    recovered_text = decrypt(ciphertext, key)

    print("--- Hill cipher example ---")
    print("Key matrix:", key)
    print("Inverse key modulo 26:", inverse_key(key))
    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)  # HIAT
    print("Decrypted:", recovered_text)  # HELP

    # Uncomment for interactive use in Google Colab.
    # key = [[3, 2], [3, 5]]  # Replace with your invertible square key matrix.
    # message = input("Enter plaintext: ")
    # ciphertext = encrypt(message, key)
    # print("Ciphertext:", ciphertext)
    # print("Decrypted:", decrypt(ciphertext, key))
