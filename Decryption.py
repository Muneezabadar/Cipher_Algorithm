
import numpy as np
import math
from typing import List, Tuple

# ---------------------------
# Helper / conversion funcs
# ---------------------------
def clean_text_letters(text: str) -> str:
   
    return ''.join(ch for ch in text.upper() if ch.isalpha())

def text_to_numbers(text: str) -> List[int]:
    
    return [ord(ch) - ord('A') for ch in text]

def numbers_to_text(nums: List[int]) -> str:
   
    return ''.join(chr(int(n) % 26 + ord('A')) for n in nums)

# ---------------------------
# Modular arithmetic helpers
# ---------------------------
def extended_gcd(a: int, b: int) -> Tuple[int,int,int]:
   
    if b == 0:
        return (1, 0, a)
    x1, y1, g = extended_gcd(b, a % b)
    return (y1, x1 - (a // b) * y1, g)

def modinv_int(a: int, m: int) -> int:
   
    a = a % m
    x, y, g = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} modulo {m} (gcd={g})")
    return x % m

def matrix_mod_inverse(K: np.ndarray, mod: int = 26) -> np.ndarray:
   
    K = np.array(K, dtype=int)
    if K.ndim != 2 or K.shape[0] != K.shape[1]:
        raise ValueError("K must be a square matrix")

    n = K.shape[0]
    
    det = int(round(np.linalg.det(K)))
    det_mod = det % mod

    if math.gcd(det_mod, mod) != 1:
        raise ValueError(f"Matrix not invertible modulo {mod}: det={det} (det mod {mod} = {det_mod}) gcd != 1")

    det_inv = modinv_int(det_mod, mod)

    
    cofactor = np.zeros((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            minor = np.delete(np.delete(K, i, axis=0), j, axis=1)
            minor_det = int(round(np.linalg.det(minor)))
            sign = (-1) ** (i + j)
            cofactor[i, j] = sign * minor_det

    adjugate = cofactor.T
    K_inv = (det_inv * adjugate) % mod
    return K_inv.astype(int)

# ---------------------------
# Playfair cipher utilities
# ---------------------------
def playfair_matrix(key: str) -> List[List[str]]:
   
    key = ''.join(ch for ch in key.upper() if ch.isalpha())
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" 
    matrix_str = ""

    for ch in key:
        ch2 = 'I' if ch == 'J' else ch
        if ch2 not in matrix_str and ch2 in alphabet:
            matrix_str += ch2

    for ch in alphabet:
        if ch not in matrix_str:
            matrix_str += ch

    matrix = [list(matrix_str[i:i+5]) for i in range(0, 25, 5)]
    return matrix

def get_char_position(matrix: List[List[str]], ch: str) -> Tuple[int,int]:
    ch = 'I' if ch == 'J' else ch
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return (r, c)
    return (-1, -1)

def decrypt_digraph(matrix: List[List[str]], a: str, b: str) -> str:
    r1, c1 = get_char_position(matrix, a)
    r2, c2 = get_char_position(matrix, b)
    if r1 == -1 or r2 == -1:
        raise ValueError(f"Character not found in Playfair matrix: {a} or {b}")

    if r1 == r2:
       
        c1 = (c1 - 1) % 5
        c2 = (c2 - 1) % 5
    elif c1 == c2:
       
        r1 = (r1 - 1) % 5
        r2 = (r2 - 1) % 5
    else:
       
        c1, c2 = c2, c1

    return matrix[r1][c1] + matrix[r2][c2]

def playfair_decrypt(ciphertext: str, key: str) -> str:
    ct = clean_text_letters(ciphertext)
    if len(ct) % 2 == 1:
        
        ct += 'X'

    matrix = playfair_matrix(key)
    out = ""
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i+1]
        out += decrypt_digraph(matrix, a, b)

    
    if out.endswith('X'):
        out = out[:-1]

    
    cleaned = []
    i = 0
    while i < len(out):
        if i+2 < len(out) and out[i] == out[i+2] and out[i+1] == 'X':
            cleaned.append(out[i])
            i += 2  
        else:
            cleaned.append(out[i])
            i += 1
    return ''.join(cleaned)

# ---------------------------
# Hill cipher (decryption)
# ---------------------------
def hill_decrypt(ciphertext: str, K: np.ndarray, m: int) -> str:
   
    ct = clean_text_letters(ciphertext)
   
    if len(ct) % m != 0:
        pad_len = m - (len(ct) % m)
        ct += 'X' * pad_len

   
    K_inv = matrix_mod_inverse(K, 26)

    C_nums = text_to_numbers(ct)
    P_nums = []
    for i in range(0, len(C_nums), m):
        block = C_nums[i:i+m]
        
        if len(block) != m:
            block += [ord('X') - ord('A')] * (m - len(block))
        C_vector = np.array(block, dtype=int)  
       
        plain_vec = np.dot(K_inv, C_vector) % 26
       
        P_nums.extend([int(x) for x in plain_vec])

    plaintext = numbers_to_text(P_nums)
   
    while plaintext.endswith('X'):
        plaintext = plaintext[:-1]
    return plaintext

# ---------------------------
# User input helpers for Hill key
# ---------------------------
def get_hill_key_matrix_from_user() -> Tuple[np.ndarray, int]:
    while True:
        try:
            print("\n--- Hill Cipher Key Input  ---")
            m = int(input("Enter the dimension (m) for the Hill key matrix (e.g., 2 for 2x2): ").strip())
            if m < 2:
                print("Dimension must be >= 2.")
                continue

            key_elements = input(f"Enter the {m*m} elements for the {m}x{m} key matrix (space-separated): ").strip()
            elements = [int(x) % 26 for x in key_elements.split()]
            if len(elements) != m*m:
                print(f"Error: you must enter exactly {m*m} integers. You entered {len(elements)}.")
                continue

            K = np.array(elements, dtype=int).reshape((m, m))

            det = int(round(np.linalg.det(K)))
            det_mod = det % 26

            if math.gcd(det_mod, 26) != 1:
                print("\n ERROR: KEY IS INVALID.")
                print(f"Determinant mod 26 is {det_mod}. gcd({det_mod}, 26) != 1 => not invertible mod 26.")
                print("Please enter a different, invertible key matrix.")
                continue

            print("\n Key is Valid!")
            print("--- Hill Key Matrix (K) Used ---")
            print(K)
            print("--------------------------------")
            return K, m

        except ValueError as e:
            print("Invalid input. Please enter integers only and try again.")
        

# ---------------------------
# High-level chained decrypt
# ---------------------------
def decrypt_chained_cipher(final_ciphertext: str, hill_K_matrix: np.ndarray, hill_m_size: int, playfair_key: str) -> str:
    print("\n\n--- Start Decryption: Hill  -> Playfair  ---")

    
    intermediate_plaintext = hill_decrypt(final_ciphertext, hill_K_matrix, hill_m_size)
    print(f"Intermediate Plaintext (After Hill Decryption): {intermediate_plaintext}")

    
    original_plaintext = playfair_decrypt(intermediate_plaintext, playfair_key)
    print(f"Original Plaintext (After Playfair Decryption): {original_plaintext}")

    return original_plaintext

# ---------------------------
# main
# ---------------------------
if __name__ == "__main__":
    print(" Two-Layer Cipher Decryption: Hill  -> Playfair ")

    playfair_key = input("Enter the key for the **Playfair Cipher** (word or phrase): ").strip()
    if not playfair_key:
        print("Error: Playfair Key cannot be empty. Exiting.")
        raise SystemExit(1)

    hill_K_matrix, hill_m_size = get_hill_key_matrix_from_user()

    final_ciphertext = input("\nEnter the final ciphertext to decrypt: ").strip()
    if not final_ciphertext:
        print("Error: Ciphertext cannot be empty. Exiting.")
        raise SystemExit(1)

    try:
        decrypted_message = decrypt_chained_cipher(final_ciphertext, hill_K_matrix, hill_m_size, playfair_key)
    except Exception as ex:
        print("An error occurred during decryption:")
        print(ex)
        raise

    print("\n==================================")
    print("FINAL DECRYPTION RESULT")
    print(f"Original Ciphertext: {final_ciphertext}")
    print(f"Recovered Message: {decrypted_message}")
    print("==================================")
