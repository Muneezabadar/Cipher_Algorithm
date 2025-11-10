# Cipher_Algorithm
This custom cipher is a product cipher that strategically integrates two well-known classical ciphers: the Playfair Cipher and the Hill Cipher. The core objective is to achieve greater security by layering the cryptographic principles of confusion and diffusion, thereby overcoming the inherent weaknesses of each individual technique

Playfair Cipher (Confusion)

The Playfair Cipher serves as the primary source of confusion (making the relationship between the key and the ciphertext as complex as possible).
* Digraph Substitution: It encrypts letters in digraphs (pairs) rather than individually.
* Obscuring Patterns: This immediately eliminates the primary vulnerability of simple substitution ciphers: single-letter frequency analysis. Because the substitution of a letter depends on its neighbor, one plaintext letter can result in multiple different ciphertext letters, scattering the statistical evidence.

Hill Cipher (Diffusion)

The Hill Cipher provides diffusion (spreading the influence of one plaintext letter over many ciphertext letters) through matrix transformation.
•	Matrix-Based Transformation: It processes blocks of letters ($m$ letters at a time) using modular arithmetic and matrix multiplication with the key matrix (K).
•	Spreading Dependencies: Changing a single letter in the Playfair output (the input to the Hill Cipher) causes changes across the entire $m$-sized block of the final ciphertext. This diffusion makes it difficult for an attacker to isolate and analyze small portions of the ciphertext.

Combined Security

By layering Playfair substitution (confusion) followed by Hill diffusion, this combined approach achieves a much higher level of security than either cipher could alone:
•	The Playfair Cipher protects the Hill Cipher from simple known-plaintext attacks targeting the Hill's small block size by making the statistical patterns of the intermediate text irregular.
•	The Hill Cipher protects the Playfair Cipher by scrambling the positions of the substituted digraphs, preventing sophisticated polygram frequency analysis.
This hybridization demonstrates how combining the unique strengths of classical ciphers can achieve a much stronger encryption scheme while remaining conceptually simple and algebraically clear.
