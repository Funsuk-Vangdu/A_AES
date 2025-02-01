# Advanced AES (AAES-512/768/1024) - Custom Encryption Algorithm

## Overview
**AAES (Advanced AES)** is a **customized encryption algorithm** inspired by the AES standard but designed for **higher security and larger key sizes**. It supports **512-bit, 768-bit, and 1024-bit** key sizes, making it suitable for **high-security applications**.

## Features
- **Block Size**: 512 bits (64 bytes) per block
- **Key Sizes**: 512-bit, 768-bit, and 1024-bit
- **Rounds**:
  - **18 rounds** for **512-bit keys**
  - **22 rounds** for **768-bit keys**
  - **26 rounds** for **1024-bit keys**
- **Custom MixColumns Transformation**
- **Custom S-Box for SubBytes Transformation**
- **Key Expansion Algorithm for Larger Key Sizes**

## Cipher Structure
The encryption process consists of multiple rounds, each performing the following transformations:

1. **AddRoundKey** - XORs the state with the round key.
2. **SubBytes** - Applies a custom S-Box transformation.
3. **ShiftRows** - Rotates the rows of the state.
4. **MixColumns** - Uses a custom **8x8 MixColumns matrix** to increase diffusion.
5. **Key Expansion** - Dynamically generates round keys from the initial key.

## Decryption Structure
Decryption follows the reverse order of encryption:
1. **Inverse AddRoundKey**
2. **Inverse ShiftRows**
3. **Inverse SubBytes** (using the inverse S-Box)
4. **Inverse MixColumns**
5. **Key Expansion (used in reverse order)**

## Installation & Dependencies
This implementation requires the following dependencies:
```bash
pip install pycryptodome
```

## Usage
### Encrypting a File
```python
from aaes import A_AES

aes = A_AES(key_length=512)  # Initialize with a 512-bit key
aes.encrypt_file('plaintext.txt', 'encrypted.aes')
```

### Decrypting a File
```python
aes.decrypt_file('encrypted.aes', 'decrypted.txt')
```

### Encrypting & Decrypting in Memory
```python
data = b"This is a test input."
padded_data = aes.pad(data)
encrypted_data = aes.encrypt_block(padded_data)
decrypted_data = aes.decrypt_block(encrypted_data)
unpadded_data = aes.unpad(decrypted_data)
print(unpadded_data)  # Should match original input
```

## Security Considerations
- The **larger key sizes** (512-bit, 768-bit, 1024-bit) make it more resistant to brute-force attacks.
- The **custom S-Box** and **MixColumns transformation** provide additional security beyond standard AES.
- Ensure proper **key management** to prevent unauthorized access.

## Future Enhancements
- Optimize performance for large files
- Implement additional padding schemes
- Support for streaming encryption

## License
This implementation is for **research and educational purposes**. Use it responsibly.


