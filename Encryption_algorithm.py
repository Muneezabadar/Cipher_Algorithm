import numpy as np

# =====================================================================
# I. SHARED/HELPER FUNCTIONS
# =====================================================================

def text_to_numbers(text):
    return [ord(char) - ord('A') for char in text]

def numbers_to_text(numbers):
    return "".join([chr(num + ord('A')) for num in numbers])

def clean_plaintext(plaintext):
    return ''.join(filter(str.isalpha, plaintext)).upper()

# =====================================================================
# II. PLAYFAIR CIPHER FUNCTIONS
# =====================================================================

def playfair_matrix(key):
    key = key.replace(" ", "").upper()
    Alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" 
    matrix_str = ""
    
    for char in key:
        char_to_add = 'I' if char == 'J' else char
        if char_to_add not in matrix_str and char_to_add in Alphabet:
            matrix_str += char_to_add

    for char in Alphabet:
        if char not in matrix_str: 
            matrix_str += char

    matrix = []
    for i in range (0, 25, 5):
        matrix.append(list(matrix_str[i:i+5]))

    return matrix

def get_char_position(matrix, char):
    char = 'I' if char == 'J' else char
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return -1, -1 

def encrypt_digraph(matrix, char1, char2):
    r1, c1 = get_char_position(matrix, char1)
    r2, c2 = get_char_position(matrix, char2)
    
    if r1 == r2:
        c1 = (c1 + 1) % 5
        c2 = (c2 + 1) % 5
    elif c1 == c2:
        r1 = (r1 + 1) % 5
        r2 = (r2 + 1) % 5
    else:
        c1, c2 = c2, c1

    return matrix[r1][c1] + matrix[r2][c2]

def prepare_plaintext(plaintext):
    plaintext = plaintext.replace(" ", "").upper().replace("J", "I")
    prepared_text = ""
    i = 0
    while i < len(plaintext):
        char1 = plaintext[i]
        if i == len(plaintext) - 1:
            prepared_text += char1 + 'X'
            break
        char2 = plaintext[i+1]
        if char1 == char2:
            prepared_text += char1 + 'X' 
            i += 1
        else:
            prepared_text += char1 + char2
            i += 2
    return prepared_text

def playfair_encrypt(plaintext, key):
    matrix = playfair_matrix(key)
    prepared_text = prepare_plaintext(plaintext)
    ciphertext = ""
    for i in range(0, len(prepared_text), 2):
        digraph = prepared_text[i:i+2]
        ciphertext += encrypt_digraph(matrix, digraph[0], digraph[1])
    return ciphertext

# =====================================================================
# III. HILL CIPHER FUNCTIONS
# =====================================================================

def get_hill_key_matrix_from_user():
    while True:
        try:
            print("\n--- Hill Cipher Key Input (Second Layer) ---")
            m = int(input("Enter the dimension (m) for the Hill key matrix (e.g., 2 for 2x2): "))
            if m < 2:
                print("Dimension must be 2 or greater.")
                continue

            key_elements = input(f"Enter the {m*m} elements for the {m}x{m} key matrix (space-separated): ")
            elements = [int(x) % 26 for x in key_elements.split()]

            if len(elements) != m * m:
                print(f"Error: You must enter exactly {m*m} elements.")
                continue
            
            K = np.array(elements).reshape((m, m))
            
            det = int(round(np.linalg.det(K)))
            det_mod = det % 26
            
            if np.gcd(det_mod, 26) != 1:
                print("\n ERROR: KEY IS INVALID.")
                print(f"Determinant mod 26 is {det_mod}. Since GCD({det_mod}, 26) is not 1 (the determinant is not coprime to 26), the decryption key cannot be found.")
                print("Please enter a different, invertible key matrix.")
                continue
            
            print("\n Key is Valid!")
            print("--- Hill Key Matrix (K) Used ---")
            print(K)
            print("--------------------------------")
            return K, m
            
        except ValueError:
            print("Invalid input. Please ensure you enter integers separated by spaces.")

def hill_encrypt(plaintext, K, m):
    
    P_clean = clean_plaintext(plaintext)
    
    padding_needed = (m - (len(P_clean) % m)) % m
    P_clean += 'X' * padding_needed
    
    P_num = text_to_numbers(P_clean)
    ciphertext_num = []
    
    for i in range(0, len(P_num), m):
        P_vector = np.array(P_num[i:i+m])
        C_vector = np.dot(K, P_vector) % 26
        ciphertext_num.extend(C_vector.tolist())
        
    ciphertext = numbers_to_text(ciphertext_num)
    
    print(f"(Hill Padding added: {P_clean[-padding_needed:]})")
    return ciphertext

# =====================================================================
# IV. MAIN EXECUTION FLOW (CHAiNED)
# =====================================================================

if __name__ == "__main__":
    
    print(" Two-Layer Cipher Chain: Playfair (L1) -> Hill (L2) ")
    
    
    
    playfair_key = input("Enter the key for the Playfair Cipher (word or phrase): ")
    if not playfair_key.strip():
        print("Error: Playfair Key cannot be empty. Exiting.")
        exit()
        
    
    hill_K_matrix, hill_m_size = get_hill_key_matrix_from_user()
    
    
    
    plaintext_msg = input("\nEnter the plaintext message to encrypt: ")
    if not plaintext_msg.strip():
        print("Error: Plaintext cannot be empty. Exiting.")
        exit()
    
    
    
    print("\n\n--- Step 1: Playfair Encryption ---")
    
    
    intermediate_ciphertext = playfair_encrypt(plaintext_msg, playfair_key)
    
    print(f"Playfair Key: {playfair_key.upper()}")
    print(f"Playfair Prepared Text: {prepare_plaintext(plaintext_msg)}")
    print(f"Intermediate Ciphertext (L1): {intermediate_ciphertext}")
    
    print("\n--- Step 2: Hill Cipher Encryption ---")
    
    
    final_ciphertext = hill_encrypt(intermediate_ciphertext, hill_K_matrix, hill_m_size)
    
    
    
    print("\n==================================")
    print("FINAL CHAINED ENCRYPTION RESULT")
    print(f"Original Message: {plaintext_msg.upper()}")
    print(f"Layer 1 (Playfair) Output: {intermediate_ciphertext}")
    print(f"Layer 2 (Hill) Input Length: {len(intermediate_ciphertext)}")
    print(f"Final Ciphertext: {final_ciphertext}")
    print("==================================")