import os
from hashlib import sha256
class A_AES:
    """
    Advanced Encryption Standard (AES) implementation with extended block size (64 bytes)
    and support for 512/768/1024-bit keys.
    """
    def __init__(self, key_length):
        self.block_size = 64  # Use consistent block size
        if key_length not in [512, 768, 1024]:
            raise ValueError("Unsupported key length. Use 512, 768, or 1024.")
        random_key = os.urandom(key_length // 8)
        self.key_length = key_length // 8
        self.key = sha256(random_key).digest()
        self.rounds = self.get_num_rounds()
        self.round_keys = self.key_expansion()


    def get_num_rounds(self):
        return {
            512: 18,  # Corrected values based on bit length
            768: 22,
            1024: 26
        }.get(self.key_length * 8, 18)  # Convert bytes to bits for comparison

    def int_to_bytes(self, value, length):
        return value.to_bytes(length, byteorder='big')

    def key_expansion(self):
        num_words = self.block_size // 8  # Number of 64-bit words per block
        total_words = num_words * (self.rounds + 1)  # Total words needed
        round_keys = [self.key[i:i + 8] for i in range(0, len(self.key), 8)]

        Rcon = [
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8,
            0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4,
            0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
        ]

        # Extend the key
        i = len(round_keys)
        while len(round_keys) < total_words:
            temp = round_keys[i - 1]  # Get the last word
            
            if i % num_words == 0:
                # Key schedule core
                temp = self.sub_word(self.rot_word(temp))
                rcon_index = (i // num_words) - 1
                if rcon_index < len(Rcon):
                    rcon_word = self.int_to_bytes(Rcon[rcon_index], 8)
                    temp = self.xor_words(temp, rcon_word)
            elif num_words > 6 and i % num_words == 4:
                temp = self.sub_word(temp)

            # XOR with word num_words positions earlier
            new_word = self.xor_words(round_keys[i - num_words], temp)
            round_keys.append(new_word)
            i += 1

        # Combine words into block-sized keys
        final_keys = []
        for i in range(0, len(round_keys), num_words):
            key_block = b''.join(round_keys[i:i + num_words])
            if len(key_block) == self.block_size:
                final_keys.append(key_block)

        print(f"Total round keys generated: {len(final_keys)}, Key size: {len(final_keys[0])}")

        # Verify we have the correct number of round keys
        if len(final_keys) != self.rounds + 1:
            raise ValueError(f"Generated {len(final_keys)} round keys, expected {self.rounds + 1}")

        return final_keys





    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]

    INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

    @staticmethod
    def sub_word(word):
        return bytes(A_AES.S_BOX[b] for b in word)

    @staticmethod
    def inv_sub_word(word):
        return bytes(A_AES.INV_S_BOX[b] for b in word)

    def sub_bytes(self, state):
        print(f"sub_bytes: state size = {len(state)}")
        return bytes(self.S_BOX[b] for b in state)


    def inv_sub_bytes(self, state):
        return bytes(self.INV_S_BOX[b] for b in state)

    @staticmethod
    def rot_word(word):
        return word[1:] + word[:1]

    @staticmethod
    def xor_words(word1, word2):
        return bytes(a ^ b for a, b in zip(word1, word2))

    def add_round_key(self, state, round_key):
        if len(round_key) != self.block_size:
            raise ValueError(f"Round key size mismatch: {len(round_key)} != {self.block_size}")
        print(f"add_round_key: state size = {len(state)}, round_key size = {len(round_key)}")
        return bytes(a ^ b for a, b in zip(state, round_key))


    def shift_rows(self, state):
        num_rows = 8  # Derived from 64-byte block size and 8 columns
        print(f"shift_rows: state size = {len(state)}")
        shifted_state = bytearray(state)
        for row in range(1, num_rows):
            shifted_state[row::num_rows] = shifted_state[row::num_rows][row:] + shifted_state[row::num_rows][:row]
        print(f"shift_rows: shifted state size = {len(shifted_state)}")
        return bytes(shifted_state)


    def inv_shift_rows(self, state):
        num_rows = 8
        shifted_state = bytearray(state)
        for row in range(1, num_rows):
            shifted_state[row::num_rows] = shifted_state[row::num_rows][-row:] + shifted_state[row::num_rows][:-row]
        return bytes(shifted_state)

    def gf_mul(self, x, y):
        if not (0 <= x <= 255 and 0 <= y <= 255):
            raise ValueError("GF multiplication inputs must be between 0 and 255")
        result = 0
        for _ in range(8):
            if y & 1:
                result ^= x
            high_bit = x & 0x80
            x = (x << 1) & 0xFF
            if high_bit:
                x ^= 0x1B
            y >>= 1
        return result



    def mix_columns(self, state):
        num_rows = 8
        num_columns = len(state) // num_rows
        print(f"mix_columns: Before = {state.hex()}")
        print(f"mix_columns: state size = {len(state)}, num_columns = {num_columns}")
        mixed_state = bytearray(self.block_size)

        #  mix matrix 
        MIX_MATRIX = [
            [7, 6, 5, 4, 3, 1, 1, 2],
            [2, 7, 6, 5, 4, 3, 1, 1],
            [1, 2, 7, 6, 5, 4, 3, 1],
            [1, 1, 2, 7, 6, 5, 4, 3],
            [3, 1, 1, 2, 7, 6, 5, 4],
            [4, 3, 1, 1, 2, 7, 6, 5],
            [5, 4, 3, 1, 1, 2, 7, 6],
            [6, 5, 4, 3, 1, 1, 2, 7],
        ]

        for col in range(num_columns):
            column = state[col * num_rows:(col + 1) * num_rows]
            for i in range(len(column)):
                mixed_state[col * num_rows + i] = sum(
                    self.gf_mul(MIX_MATRIX[i][j], column[j]) for j in range(len(column))
                ) & 0xFF

        print(f"mix_columns: mixed state size = {len(mixed_state)}")
        print(f"mix_columns: After = {bytes(mixed_state).hex()}")
        return bytes(mixed_state)


    def inv_mix_columns(self, state):
        num_rows = 8
        num_columns = len(state) // num_rows
        print(f"inv_mix_columns: Before = {state.hex()}")
        mixed_state = bytearray(self.block_size)
        inv_mix_matrix = [
            [14, 11, 13, 9, 15, 10, 5, 3],
            [3, 14, 11, 13, 9, 15, 10, 5],
            [5, 3, 14, 11, 13, 9, 15, 10],
            [10, 5, 3, 14, 11, 13, 9, 15],
            [15, 10, 5, 3, 14, 11, 13, 9],
            [9, 15, 10, 5, 3, 14, 11, 13],
            [13, 9, 15, 10, 5, 3, 14, 11],
            [11, 13, 9, 15, 10, 5, 3, 14],
        ]

        for col in range(num_columns):
            column = state[col * num_rows:(col + 1) * num_rows]
            for i in range(len(column)):
                mixed_state[col * num_rows + i] = sum(
                    self.gf_mul(inv_mix_matrix[i][j], column[j]) for j in range(len(column))
                ) & 0xFF
        print(f"inv_mix_columns: After = {bytes(mixed_state).hex()}")
        return bytes(mixed_state)
       

    # 
    def encrypt_block(self, block):
        

   
        """
        Encrypts a single block of data.
        
        Args:
            block (bytes): A block of data to encrypt (must be BLOCK_SIZE bytes)
            
        Returns:
            bytes: The encrypted block
            
        Raises:
            ValueError: If block size is invalid
        """
        if len(block) != self.block_size:
            raise ValueError(f"Invalid block size: {len(block)}. Block must be of size {self.block_size}.")
        
        print(f"Encrypting block of size {len(block)}")
        num_rounds = self.get_num_rounds()
        state = block
        print(f"Initial state: {state}")

        # Initial round
        state = self.add_round_key(state, self.round_keys[0])
        print(f"After initial round: {state}")

        # Main rounds
        for round in range(1, num_rounds):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_keys[round])
            print(f"After round {round}: {state}")

        # Final round (without mix_columns)
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_keys[num_rounds])
        print(f"Final state: {state}")

        return state


    def decrypt_block(self, block):
        if len(block) != self.block_size:
            raise ValueError(f"Invalid block size: {len(block)}. Expected {self.block_size}.")

        state = block
        state = self.add_round_key(state, self.round_keys[-1])

        for round_num in range(self.rounds - 1, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, self.round_keys[round_num])
            state = self.inv_mix_columns(state)

        # Final round (without InvMixColumns)
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.round_keys[0])

        return state





    
   
    def pad(self, data):
        padding_len = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    def unpad(self, data):
        if not data:
            raise ValueError("Empty data cannot be unpadded")
        padding_len = data[-1]
        if padding_len < 1 or padding_len > self.block_size:
            raise ValueError(f"Invalid padding length: {padding_len}")
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid padding")
        return data[:-padding_len]








    def encrypt_file(self, input_path, output_path):
        print(f"🔑 Encryption Key: {self.key.hex()}")  # Print encryption key

        with open(input_path, 'rb') as f:
            data = f.read()
        
        padded_data = self.pad(data)
        print(f"Original data length: {len(data)}")
        print(f"Padded data length: {len(padded_data)}")
        print(f"Padded plaintext before encryption (last block): {padded_data[-self.block_size:].hex()}")


        encrypted_data = b""
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]
            encrypted_block = self.encrypt_block(block)
            encrypted_data += encrypted_block
            print(f"Block {i // self.block_size}: Encrypted block length = {len(encrypted_block)}")

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"Encrypted data length: {len(encrypted_data)}")
        print(f"Encrypted Data: {encrypted_data.hex()}")

        print(f"Encrypted data length: {len(encrypted_data)}")
        print(f"Padded plaintext (last block before encryption): {padded_data[-self.block_size:].hex()}")




    def decrypt_file(self, input_file, output_file):
        print(f"🔑 Decryption Key: {self.key.hex()}")  # Print decryption key

        with open(input_file, "rb") as f:
            data = f.read()
        
        print(f"Encrypted data length: {len(data)}")

        decrypted_data = b""
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            decrypted_block = self.decrypt_block(block)
            decrypted_data += decrypted_block
            print(f"Block {i // self.block_size}: Decrypted block length = {len(decrypted_block)}")

        print(f"Decrypted data length before unpadding: {len(decrypted_data)}")

        # 🔴 **Debug last decrypted block before unpadding**
        print(f"Last decrypted block before unpadding: {decrypted_data[-self.block_size:].hex()}")
        print(f"Decrypted Data Before Unpadding: {decrypted_data.hex()}")

        # Now try to unpad the decrypted data
        decrypted_data = self.unpad(decrypted_data)

        with open(output_file, "wb") as f:
            f.write(decrypted_data)
        print(f"Last decrypted block before unpadding: {decrypted_data[-self.block_size:].hex()}")

        print(f"Final decrypted data length: {len(decrypted_data)}")


