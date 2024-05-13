import base64
import numpy as np

class AES:
    def __init__(self, key):
        self.key = key

        # AES round constants
        self.round_constants = np.array([
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        ], dtype=np.uint8)

        # Precomputed S-box
        self.s_box = np.array([
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
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ], dtype=np.uint8)

        # Inverse S-box
        self.inv_s_box = np.array([
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
        ], dtype=np.uint8)

    def aes_sub_bytes(self, state):
        """Substitute bytes transformation."""
        for i in range(4):
            for j in range(4):
                state[i, j] = self.s_box[state[i, j]]
        return state

    def aes_shift_rows(self, state):
        """Shift rows transformation."""
        # Create an array with the same shape and data type was `state`
        shifted_state = np.zeros_like(state)

        # First row remains unchanged
        shifted_state[0, :] = state[0, :]

        # Second row is shifted one position to the left
        shifted_state[1, 0] = state[1, 1]
        shifted_state[1, 1] = state[1, 2]
        shifted_state[1, 2] = state[1, 3]
        shifted_state[1, 3] = state[1, 0]

        # Third row is shifted two positions to the left
        shifted_state[2, 0] = state[2, 2]
        shifted_state[2, 1] = state[2, 3]
        shifted_state[2, 2] = state[2, 0]
        shifted_state[2, 3] = state[2, 1]

        # Fourth row is shifted three positions to the left
        shifted_state[3, 0] = state[3, 3]
        shifted_state[3, 1] = state[3, 0]
        shifted_state[3, 2] = state[3, 1]
        shifted_state[3, 3] = state[3, 2]

        return shifted_state

    def aes_mix_columns(self, state):
        """Mix columns transformation."""
        mix_matrix = np.array([
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ], dtype=np.uint8)

        state = np.dot(mix_matrix, state)
        return state % 0x100

    def aes_key_expansion(self):
        """Generate round keys from the initial key."""
        key_words = np.frombuffer(self.key, dtype=np.uint8)

        # Key schedule core
        def key_schedule_core(word, round_num):
            # Rotate word
            word = np.roll(word, -1)

            # Substitute bytes
            for i in range(4):
                word[i] = self.s_box[word[i]]

            # XOR with round constant
            word[0] ^= self.round_constants[round_num]

            return word

        # Get the last word of the key
        last_word = key_words[-4:].copy()

        # Generate new words
        new_words = [last_word]

        for round_num in range(1, 10):
            # Perform key schedule core
            last_word = key_schedule_core(last_word, round_num)
            new_words.append(last_word)

            # XOR with the previous word
            prev_word = key_words[(round_num - 1) * 4:round_num * 4]
            if len(prev_word) < 4:
                prev_word = np.zeros(4, dtype=np.uint8)  # Pad with zeros if necessary
            last_word = np.bitwise_xor(last_word, prev_word)
            new_words.append(last_word)

        # Convert words to a 2D array
        round_keys = np.array(new_words).reshape((-1, 4)).T
        return round_keys

    def aes_add_round_key(self, state, round_key):
        """Add round key transformation."""
        return state ^ round_key

    def aes_encrypt_block(self, block):
        """Encrypt a single block."""
        # Encode the byte string as ASCII or UTF-8 to get integers
        block_ints = [int(byte) for byte in block]

        # Pad or truncate the list to ensure it's exactly 16 bytes long
        block_ints = block_ints[:16] + [0] * (16 - len(block_ints))

        # Convert the list of integers to a NumPy array and reshape into a 4x4 matrix
        state = np.array(block_ints, dtype=np.uint8).reshape((4, 4))

        # Key expansion
        round_keys = self.aes_key_expansion()

        # Initial round key addition
        state = self.aes_add_round_key(state, round_keys[:, 0])

        # Main rounds
        for i in range(1, round_keys.shape[1]):
            state = self.aes_sub_bytes(state)
            state = self.aes_shift_rows(state)
            state = self.aes_mix_columns(state)
            state = self.aes_add_round_key(state, round_keys[:, i])

        # Final round (no mix columns)
        state = self.aes_sub_bytes(state)
        state = self.aes_shift_rows(state)
        state = self.aes_add_round_key(state, round_keys[:, -1])

        # Convert state back to bytes
        encrypted_block = state.flatten().tolist()
        return encrypted_block

    def aes_encrypt(self, plaintext):
        """Encrypt plaintext."""
        # Pad the plaintext if needed
        if len(plaintext) % 16 != 0:
            padding_length = 16 - (len(plaintext) % 16)
            plaintext += bytes([padding_length] * padding_length)

        # Divide the plaintext into blocks
        plaintext_blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]

        # Encrypt each block
        encrypted_blocks = []
        for block in plaintext_blocks:
            encrypted_block = self.aes_encrypt_block(block)

            # Encode the encrypted block using Base64
            encrypted_base64 = base64.b64encode(bytes(encrypted_block)).decode('utf-8')
            encrypted_blocks.append(encrypted_base64)


        # Return the encrypted blocks
        return encrypted_base64
    

    def aes_inv_sub_bytes(self, state):
        """Apply inverse SubBytes operation."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_s_box[state[i][j]]
        return state

    def aes_inv_shift_rows(self, state):
        """Inverse Shift rows transformation."""
        # Create an array with the same shape and data type was `state`
        shifted_state = np.zeros_like(state)

        # First row remains unchanged
        shifted_state[0, :] = state[0, :]

        # Second row is shifted one position to the left
        shifted_state[1, 0] = state[1, 3]
        shifted_state[1, 1] = state[1, 0]
        shifted_state[1, 2] = state[1, 1]
        shifted_state[1, 3] = state[1, 2]

        # Third row is shifted two positions to the left
        shifted_state[2, 0] = state[2, 2]
        shifted_state[2, 1] = state[2, 3]
        shifted_state[2, 2] = state[2, 0]
        shifted_state[2, 3] = state[2, 1]

        # Fourth row is shifted three positions to the left
        shifted_state[3, 0] = state[3, 1]
        shifted_state[3, 1] = state[3, 2]
        shifted_state[3, 2] = state[3, 3]
        shifted_state[3, 3] = state[3, 0]

        return shifted_state
    
    def aes_inv_mix_columns(self, state):
        """Apply inverse MixColumns operation."""
        # Define the fixed matrix for inverse MixColumns
        inv_mix_column_matrix = np.array([
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
        ], dtype=np.uint8)

        # Perform matrix multiplication
        state = np.dot(state, inv_mix_column_matrix)

        return state

    def aes_decrypt_block(self, encrypted_block):
        """Decrypt a single block."""
        # Convert the Base64-encoded string back to bytes
        encrypted_bytes = base64.b64decode(encrypted_block)

        # Convert the bytes to a NumPy array and reshape into a 4x4 matrix
        state = np.array(list(encrypted_bytes), dtype=np.uint8).reshape((4, 4))

        # Key expansion
        round_keys = self.aes_key_expansion()

        # Final round key addition
        state = self.aes_add_round_key(state, round_keys[:, -1])

        # Main rounds (in reverse order)
        for i in range(round_keys.shape[1] - 2, 0, -1):
            state = self.aes_inv_shift_rows(state)
            state = self.aes_inv_sub_bytes(state)
            state = self.aes_add_round_key(state, round_keys[:, i])
            state = self.aes_inv_mix_columns(state)


        # Initial round (in reverse order)
        state = self.aes_inv_shift_rows(state)
        state = self.aes_inv_sub_bytes(state)
        state = self.aes_add_round_key(state, round_keys[:, 0])

        # Convert state back to bytes
        decrypted_block = state.flatten().tolist()

        # Remove padding
        #padding_length = decrypted_block[-1]
        #decrypted_block = decrypted_block[:-padding_length]

        # Convert decrypted block to bytes
        decrypted_bytes = bytes(decrypted_block)

        return decrypted_bytes

# Example usage:
# key = b'ThisIsA16ByteKey'
# aes = AES(key)
# plaintext = b'HelloWorld123456'
# encrypted_block = aes.aes_encrypt(plaintext)
# print(encrypted_block)

# decrypted_block = aes.aes_decrypt_block(encrypted_block)
# print(decrypted_block)
# print(base64.b64encode(decrypted_block).decode('utf-8'))