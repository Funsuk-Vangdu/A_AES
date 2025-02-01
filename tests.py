from aes import A_AES

def test_encryption():
    input_file = "example.pdf"
    encrypted_file = "encrypted.pdf"
    decrypted_file = "decrypted.pdf"

    for key_length in [512, 768, 1024]:
        print(f"Testing with {key_length}-bit key...")
        aes = A_AES(key_length=key_length)

        aes.encrypt_file(input_file, encrypted_file)
        aes.decrypt_file(encrypted_file, decrypted_file)

        with open(input_file, 'rb') as f:
            original = f.read()
        with open(decrypted_file, 'rb') as f:
            decrypted = f.read()

        assert original == decrypted, f"Decryption failed for key size {key_length}!"
        print(f"Test passed for {key_length}-bit key!")
    

if __name__ == "__main__":
    test_encryption()
