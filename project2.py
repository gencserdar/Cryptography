import os
import struct
import base64
import hashlib

#INPUTS TO TEST
ASCON_INPUT = b"Hello, ASCON!"
TINY_JAMBU_INPUT = b"Hello, TinyJambu!"
CBC_INPUT = b"This is a CBC mode test!" 
OFB_INPUT = b"This is an OFB mode test!"

# Simplified implementation of Ascon-128a cipher
class Ascon:
    def __init__(self, key: bytes, nonce: bytes):
        """
        Initialize the Ascon cipher with a 128-bit key and a 128-bit nonce.

        Args:
            key (bytes): 128-bit key (16 bytes).
            nonce (bytes): 128-bit nonce (16 bytes).

        Raises:
            AssertionError: If the key or nonce is not 16 bytes long.
        """
        assert len(key) == 16, "Key must be 128 bits."
        assert len(nonce) == 16, "Nonce must be 128 bits."
        self.key = key
        self.nonce = nonce

    def _ascon_permutation(self, state, rounds):
        """
        Simplified placeholder for Ascon permutation function.

        Args:
            state (list[int]): State to permute (list of integers).
            rounds (int): Number of permutation rounds.

        Returns:
            list[int]: Permuted state.
        """
        # Simplified permutation logic
        for _ in range(rounds):
            state = [((x << 1) ^ (x >> 3)) & 0xFFFFFFFFFFFFFFFF for x in state]
        return state

    def _encrypt_block_cbc(self, block: bytes) -> bytes:
        """
        Simplified CBC encryption for a single block.

        Args:
            block (bytes): 16-byte plaintext block.

        Returns:
            bytes: 16-byte ciphertext block.

        Raises:
            ValueError: If the block is not 16 bytes.
        """
        if len(block) != 16:
            raise ValueError("Block must be exactly 16 bytes.")
        
        # Create initial state using nonce and key
        state = list(struct.unpack("<4Q", self.nonce + self.key))
        state = self._ascon_permutation(state, 12)
        
        # XOR block values with state
        block_vals = struct.unpack("<2Q", block)
        encrypted_vals = tuple(block_vals[i] ^ state[i % 4] for i in range(len(block_vals)))
        
        return struct.pack("<2Q", *encrypted_vals)

    def _decrypt_block_cbc(self, block: bytes) -> bytes:
        """
        Simplified CBC decryption for a single block.

        Args:
            block (bytes): 16-byte ciphertext block.

        Returns:
            bytes: 16-byte plaintext block.

        Raises:
            ValueError: If the block is not 16 bytes.
        """
        if len(block) != 16:
            raise ValueError("Block must be exactly 16 bytes.")
        
        # Rebuild state using nonce and key
        state = list(struct.unpack("<4Q", self.nonce + self.key))
        state = self._ascon_permutation(state, 12)
        
        # XOR block values with state
        block_vals = struct.unpack("<2Q", block)
        decrypted_vals = tuple(block_val ^ state[i % 4] for i, block_val in enumerate(block_vals))
        
        return struct.pack("<2Q", *decrypted_vals)

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        """
        Encrypt plaintext using Ascon-like cipher with associated data.

        Args:
            plaintext (bytes): Plaintext to encrypt.
            associated_data (bytes): Associated data for integrity.

        Returns:
            bytes: Ciphertext with 8-byte authentication tag appended.
        """
        # Initialize state with nonce and key
        state = list(struct.unpack("<4Q", self.nonce + self.key))
        state = self._ascon_permutation(state, 12)

        # Absorb associated data into the state
        for i in range(0, len(associated_data), 8):
            block = associated_data[i:i+8].ljust(8, b"\x00")
            state[0] ^= struct.unpack("<Q", block)[0]
            state = self._ascon_permutation(state, 6)

        # Encrypt plaintext block by block
        ciphertext = b""
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i+8].ljust(8, b"\x00")
            val = struct.unpack("<Q", block)[0] ^ state[0]
            ciphertext += struct.pack("<Q", val)
            state[0] = val
            state = self._ascon_permutation(state, 6)

        # Finalize and compute tag
        state[0] ^= struct.unpack("<Q", self.key[:8])[0]
        state = self._ascon_permutation(state, 12)
        tag = struct.pack("<Q", state[0])

        return ciphertext + tag

    def decrypt(self, ciphertext: bytes, associated_data: bytes, skip_tag_check=False) -> bytes:
        """
        Decrypt ciphertext using Ascon-like cipher with associated data.

        Args:
            ciphertext (bytes): Ciphertext to decrypt (including 8-byte tag).
            associated_data (bytes): Associated data for integrity.
            skip_tag_check (bool): Skip integrity check if True.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            ValueError: If the ciphertext is too short or tag verification fails.
        """
        if not skip_tag_check and len(ciphertext) < 8:
            raise ValueError("Ciphertext too short.")

        # Separate ciphertext and tag
        if not skip_tag_check:
            tag = ciphertext[-8:]
            c_no_tag = ciphertext[:-8]
        else:
            c_no_tag = ciphertext

        # Rebuild initial state
        state = list(struct.unpack("<4Q", self.nonce + self.key))
        state = self._ascon_permutation(state, 12)

        # Absorb associated data into the state
        for i in range(0, len(associated_data), 8):
            block = associated_data[i:i+8].ljust(8, b"\x00")
            state[0] ^= struct.unpack("<Q", block)[0]
            state = self._ascon_permutation(state, 6)

        # Decrypt ciphertext block by block
        plaintext = b""
        for i in range(0, len(c_no_tag), 8):
            block_val = struct.unpack("<Q", c_no_tag[i:i+8].ljust(8, b"\x00"))[0]
            dec_val = block_val ^ state[0]
            plaintext += struct.pack("<Q", dec_val)
            state[0] = block_val
            state = self._ascon_permutation(state, 6)

        # Verify tag
        if not skip_tag_check:
            state[0] ^= struct.unpack("<Q", self.key[:8])[0]
            state = self._ascon_permutation(state, 12)
            expected_tag = struct.pack("<Q", state[0])
            if expected_tag != tag:
                raise ValueError("Tag mismatch! Integrity check failed.")

        return plaintext.rstrip(b"\x00")


# Simplified implementation of the TinyJambu cipher
class TinyJambu:
    def __init__(self, key: bytes):
        """
        Initialize the TinyJambu cipher with a 128-bit key.

        Args:
            key (bytes): 128-bit key (16 bytes).

        Raises:
            AssertionError: If the key is not 16 bytes long.
        """
        assert len(key) == 16, "Key must be 128 bits."
        self.key_words = struct.unpack("<IIII", key)  # Split key into four 32-bit words

    def _tinyjambu_round(self, state, key_word):
        """
        Perform one round of the TinyJambu permutation.

        Args:
            state (list[int]): Current state (list of 4 integers).
            key_word (int): 32-bit key word for the current round.

        Returns:
            list[int]: Updated state after one round.
        """
        # Extract individual state values
        s0, s1, s2, s3 = state

        # Calculate feedback from the current state and key word
        t1 = ((s1 >> 15) | (s2 << 17)) & 0xFFFFFFFF
        t2 = ((s2 >> 6)  | (s3 << 26)) & 0xFFFFFFFF
        t3 = ((s2 >> 21) | (s3 << 11)) & 0xFFFFFFFF
        t4 = ((s2 >> 27) | (s3 << 5))  & 0xFFFFFFFF
        feedback = s0 ^ t1 ^ t2 ^ t3 ^ t4 ^ key_word

        # Update state
        return [s1, s2, s3, feedback & 0xFFFFFFFF]

    def _tinyjambu_permutation(self, state, rounds=128):
        """
        Perform multiple rounds of the TinyJambu permutation.

        Args:
            state (list[int]): Initial state (list of 4 integers).
            rounds (int): Number of rounds to perform.

        Returns:
            list[int]: Final state after permutation.
        """
        for i in range(rounds):
            kw = self.key_words[i % 4]  # Select key word in a round-robin manner
            state = self._tinyjambu_round(state, kw)
        return state

    def encrypt(self, plaintext: bytes, nonce: bytes, associated_data: bytes) -> bytes:
        """
        Encrypt plaintext using TinyJambu with associated data.

        Args:
            plaintext (bytes): Plaintext to encrypt.
            nonce (bytes): Nonce (16 bytes).
            associated_data (bytes): Associated data for integrity.

        Returns:
            bytes: Ciphertext with 4-byte authentication tag appended.

        Raises:
            ValueError: If the nonce is not 16 bytes.
        """
        if len(nonce) != 16:
            raise ValueError("Nonce must be 16 bytes.")
        
        # Initialize state with nonce and perform initial permutation
        s = list(struct.unpack("<IIII", nonce))
        s = self._tinyjambu_permutation(s, 384)

        # Absorb associated data into the state
        ad_off = 0
        while ad_off < len(associated_data):
            block = associated_data[ad_off:ad_off+4].ljust(4, b"\x00")
            val = struct.unpack("<I", block)[0]
            s[0] ^= val
            s = self._tinyjambu_permutation(s, 128)
            ad_off += 4

        # Encrypt plaintext block by block
        ciphertext = b""
        pt_off = 0
        while pt_off < len(plaintext):
            block = plaintext[pt_off:pt_off+4].ljust(4, b"\x00")
            val = struct.unpack("<I", block)[0] ^ s[0]
            ciphertext += struct.pack("<I", val)
            s = self._tinyjambu_permutation(s, 128)
            pt_off += 4

        # Compute authentication tag
        tag = struct.pack("<I", s[0])

        return ciphertext + tag

    def decrypt(self, ciphertext: bytes, nonce: bytes, associated_data: bytes) -> bytes:
        """
        Decrypt ciphertext using TinyJambu with associated data.

        Args:
            ciphertext (bytes): Ciphertext to decrypt (including 4-byte tag).
            nonce (bytes): Nonce (16 bytes).
            associated_data (bytes): Associated data for integrity.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            ValueError: If the nonce is not 16 bytes or the ciphertext is too short.
            ValueError: If tag verification fails.
        """
        if len(nonce) != 16:
            raise ValueError("Nonce must be 16 bytes.")
        if len(ciphertext) < 4:
            raise ValueError("Ciphertext too short.")

        # Separate ciphertext and tag
        tag = ciphertext[-4:]
        c_no_tag = ciphertext[:-4]

        # Initialize state with nonce and perform initial permutation
        s = list(struct.unpack("<IIII", nonce))
        s = self._tinyjambu_permutation(s, 384)

        # Absorb associated data into the state
        ad_off = 0
        while ad_off < len(associated_data):
            block = associated_data[ad_off:ad_off+4].ljust(4, b"\x00")
            val = struct.unpack("<I", block)[0]
            s[0] ^= val
            s = self._tinyjambu_permutation(s, 128)
            ad_off += 4

        # Decrypt ciphertext block by block
        plaintext = b""
        ct_off = 0
        while ct_off < len(c_no_tag):
            block = c_no_tag[ct_off:ct_off+4].ljust(4, b"\x00")
            val = struct.unpack("<I", block)[0]
            dec_val = val ^ s[0]
            plaintext += struct.pack("<I", dec_val)
            s = self._tinyjambu_permutation(s, 128)
            ct_off += 4

        # Verify authentication tag
        if struct.pack("<I", s[0]) != tag:
            raise ValueError("Tag mismatch! Integrity check failed.")

        return plaintext.rstrip(b"\x00")


# Combined tool for lightweight encryption using Ascon and TinyJambu
class LightweightEncryptionTool:
    def __init__(self, key: bytes):
        """
        Initialize the LightweightEncryptionTool with a 128-bit key.

        Args:
            key (bytes): 128-bit key (16 bytes).

        Raises:
            AssertionError: If the key is not 16 bytes long.
        """
        assert len(key) == 16, "Key must be 128 bits."
        self.ascon_nonce = os.urandom(16)  # Generate a random 128-bit nonce for Ascon
        self.jambu_nonce = os.urandom(16)  # Generate a random 128-bit nonce for TinyJambu
        self.ascon_engine = Ascon(key, self.ascon_nonce)  # Initialize Ascon engine
        self.jambu_engine = TinyJambu(key)  # Initialize TinyJambu engine

    # Ascon Encryption/Decryption
    def encrypt_ascon(self, plaintext: bytes, associated_data: bytes) -> bytes:
        """
        Encrypt plaintext using Ascon.

        Args:
            plaintext (bytes): The plaintext to encrypt.
            associated_data (bytes): Associated data for integrity.

        Returns:
            bytes: Ciphertext with appended tag.
        """
        return self.ascon_engine.encrypt(plaintext, associated_data)

    def decrypt_ascon(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        """
        Decrypt ciphertext using Ascon.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
            associated_data (bytes): Associated data for integrity.

        Returns:
            bytes: Decrypted plaintext.
        """
        return self.ascon_engine.decrypt(ciphertext, associated_data)

    # TinyJambu Encryption/Decryption
    def encrypt_tinyjambu(self, plaintext: bytes, associated_data: bytes) -> bytes:
        """
        Encrypt plaintext using TinyJambu.

        Args:
            plaintext (bytes): The plaintext to encrypt.
            associated_data (bytes): Associated data for integrity.

        Returns:
            bytes: Ciphertext with appended tag.
        """
        return self.jambu_engine.encrypt(plaintext, self.jambu_nonce, associated_data)

    def decrypt_tinyjambu(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        """
        Decrypt ciphertext using TinyJambu.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
            associated_data (bytes): Associated data for integrity.

        Returns:
            bytes: Decrypted plaintext.
        """
        return self.jambu_engine.decrypt(ciphertext, self.jambu_nonce, associated_data)

    # CBC Mode (Block Cipher Mode)
    def cbc_encrypt(self, plaintext: bytes, iv: bytes, algorithm):
        """
        Encrypt plaintext using CBC mode with a given block cipher algorithm.

        Args:
            plaintext (bytes): The plaintext to encrypt.
            iv (bytes): Initialization vector (16 bytes).
            algorithm: Block cipher algorithm implementing _encrypt_block_cbc.

        Returns:
            bytes: Encrypted ciphertext.

        Raises:
            ValueError: If the IV is not 16 bytes.
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes.")
        
        ciphertext = b""
        prev_block = iv  # Initialize previous block to IV
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16].ljust(16, b"\x00")  # Pad block to 16 bytes
            # XOR with the previous block and encrypt
            xored = bytes([block[j] ^ prev_block[j] for j in range(16)])
            encrypted = algorithm._encrypt_block_cbc(xored)
            ciphertext += encrypted
            prev_block = encrypted  # Update previous block
        return ciphertext

    def cbc_decrypt(self, ciphertext: bytes, iv: bytes, algorithm):
        """
        Decrypt ciphertext using CBC mode with a given block cipher algorithm.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
            iv (bytes): Initialization vector (16 bytes).
            algorithm: Block cipher algorithm implementing _decrypt_block_cbc.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            ValueError: If the IV is not 16 bytes or ciphertext is not a multiple of 16 bytes.
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes.")
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of 16 bytes.")

        plaintext = b""
        prev_block = iv  # Initialize previous block to IV
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted = algorithm._decrypt_block_cbc(block)
            # XOR decrypted block with the previous block
            out_block = bytes([decrypted[j] ^ prev_block[j] for j in range(16)])
            plaintext += out_block
            prev_block = block  # Update previous block
        return plaintext.rstrip(b"\x00")  # Remove padding

    # OFB Mode (Block Cipher Mode)
    def ofb_encrypt(self, plaintext: bytes, iv: bytes, algorithm):
        """
        Encrypt plaintext using OFB mode with a given block cipher algorithm.

        Args:
            plaintext (bytes): The plaintext to encrypt.
            iv (bytes): Initialization vector (16 bytes).
            algorithm: Block cipher algorithm.

        Returns:
            bytes: Encrypted ciphertext.

        Raises:
            ValueError: If the IV is not 16 bytes.
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes.")
        
        ciphertext = b""
        feedback = iv  # Initialize feedback to IV
        for i in range(0, len(plaintext), 16):
            # Generate keystream block
            keystream = algorithm.encrypt(feedback, b"")[:16]
            block = plaintext[i:i+16].ljust(16, b"\x00")
            # XOR plaintext block with keystream block
            out_block = bytes([block[j] ^ keystream[j] for j in range(16)])
            ciphertext += out_block
            feedback = keystream  # Update feedback
        return ciphertext

    def ofb_decrypt(self, ciphertext: bytes, iv: bytes, algorithm):
        """
        Decrypt ciphertext using OFB mode with a given block cipher algorithm.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.
            iv (bytes): Initialization vector (16 bytes).
            algorithm: Block cipher algorithm.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            ValueError: If the IV is not 16 bytes.
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes.")

        plaintext = b""
        feedback = iv  # Initialize feedback to IV
        for i in range(0, len(ciphertext), 16):
            # Generate keystream block
            keystream = algorithm.encrypt(feedback, b"")[:16]
            block = ciphertext[i:i+16].ljust(16, b"\x00")
            # XOR ciphertext block with keystream block
            out_block = bytes([block[j] ^ keystream[j] for j in range(len(block))])
            plaintext += out_block
            feedback = keystream  # Update feedback
        return plaintext.rstrip(b"\x00")  # Remove padding


#
# 4) (c) EXTRACT FUNCTION & (d) VERIFY FUNCTION
#

MARKER = b"META:"

def extract_metadata(file_path: str, user_id: str, tool: LightweightEncryptionTool):
    """
    c) 
      - Read the file. If 'META:' found, we treat everything from that point on as old metadata
        and remove it from the "main content."
      - Compute SHA-256 of main content
      - Build "user_id=...,hash=..." 
      - Encrypt with Ascon under a random nonce
      - Append `META:` + base64(nonce + ciphertext)
    """
    with open(file_path, "rb") as f:
        content = f.read()

    # remove old metadata if any
    pos = content.find(MARKER)
    if pos != -1:
        main_content = content[:pos]
    else:
        main_content = content

    # compute hash
    file_hash = hashlib.sha256(main_content).hexdigest()
    meta_str = f"user_id={user_id};hash={file_hash}"
    meta_bytes = meta_str.encode("utf-8")

    # new random nonce
    new_nonce = os.urandom(16)
    # Ascon engine with new_nonce
    ascon_temp = Ascon(tool.ascon_engine.key, new_nonce)
    encrypted = ascon_temp.encrypt(meta_bytes, b"")  # no AD
    # store: [nonce + encrypted] in base64
    b64_meta = base64.b64encode(new_nonce + encrypted)

    # rewrite file: main_content + MARKER + b64
    with open(file_path, "wb") as f:
        f.write(main_content)
        f.write(MARKER)
        f.write(b64_meta)

    print(f"\n[extract_metadata] user_id='{user_id}', stored_hash={file_hash}")
    print("Metadata appended to file.")


def verify_metadata(file_path: str, tool: LightweightEncryptionTool):
    """
    d) 
      - Locates the first 'META:' marker
      - Base64-decodes => [nonce + ciphertext]
      - Decrypt => "user_id=...,hash=..."
      - Re-hash the main content => compare
    """
    if not os.path.exists(file_path):
        print("File not found.")  # Check if the file exists
        return

    with open(file_path, "rb") as f:
        content = f.read()  # Read the entire file content

    # Locate the marker position
    pos = content.find(MARKER)
    if pos == -1:
        print("No metadata found. Can't verify.")  # If marker is missing, exit
        return

    # Split the content into main data and Base64 metadata
    main_content = content[:pos]  # Main content before the marker
    b64_part = content[pos + len(MARKER):]  # Metadata following the marker

    try:
        # Decode the Base64-encoded metadata
        raw = base64.b64decode(b64_part)
    except Exception as e:
        print("Base64 decode error:", e)  # Handle invalid Base64 data
        return

    if len(raw) < 16:
        print("Not enough data for [nonce + ciphertext].")  # Ensure sufficient data for decryption
        return

    # Extract the nonce and ciphertext from the decoded metadata
    used_nonce = raw[:16]
    ascon_cipher = raw[16:]

    # Rebuild a local Ascon instance using the extracted nonce
    local_ascon = Ascon(tool.ascon_engine.key, used_nonce)
    try:
        # Decrypt the ciphertext to obtain the metadata string
        dec = local_ascon.decrypt(ascon_cipher, b"")
    except ValueError as e:
        print(f"Decryption error: {e}")  # Handle decryption failure
        return

    # Decode the decrypted metadata into a string format
    meta_str = dec.decode("utf-8")  # Metadata format: "user_id=...,hash=..."
    pairs = meta_str.split(";")  # Split metadata into key-value pairs
    meta_dict = {}
    for p in pairs:
        if "=" in p:
            k, v = p.split("=")  # Extract keys and values
            meta_dict[k] = v

    # Extract the stored hash and user_id from the metadata
    stored_hash = meta_dict.get("hash", "")
    user_id = meta_dict.get("user_id", "(unknown)")

    # Recompute the hash of the main content
    curr_hash = hashlib.sha256(main_content).hexdigest()

    # Print extracted and recomputed information for verification
    print(f"\n[verify_metadata] user_id='{user_id}', stored_hash={stored_hash}")
    print(f"[verify_metadata] current_hash={curr_hash}")

    # Compare the recomputed hash with the stored hash
    if curr_hash == stored_hash:
        print("File is intact. No changes detected.")  # Integrity verified
    else:
        print("File has changed or integrity is compromised!")  # Integrity check failed


#
# 5) DEMO (a), (b)
#

def test_lightweight_algorithms(tool: LightweightEncryptionTool):
    """
    (a) Demonstrate Ascon & TinyJambu with test data
    """
    print("======== ASCON-128a Test ========")
    pt_ascon = ASCON_INPUT
    ad_ascon = b"ASCON_AD"
    ct_ascon = tool.encrypt_ascon(pt_ascon, ad_ascon)
    print("ASCON Ciphertext+Tag:", ct_ascon)

    try:
        dec_ascon = tool.decrypt_ascon(ct_ascon, ad_ascon)
        print("ASCON Decrypted:", dec_ascon)
    except ValueError as e:
        print("ASCON Decryption Error:", e)

    print("\n======== TinyJambu Test ========")
    pt_jambu = TINY_JAMBU_INPUT
    ad_jambu = b"JAMBU_AD"
    ct_jambu = tool.encrypt_tinyjambu(pt_jambu, ad_jambu)
    print("TinyJambu Ciphertext+Tag:", ct_jambu)

    try:
        dec_jambu = tool.decrypt_tinyjambu(ct_jambu, ad_jambu)
        print("TinyJambu Decrypted:", dec_jambu)
    except ValueError as e:
        print("TinyJambu Decryption Error:", e)


def test_cbc_ofb(tool: LightweightEncryptionTool):
    """
    (b) Demonstrate CBC & OFB with Ascon engine
    """
    iv = os.urandom(16)

    print("\n======== CBC Mode Test ========")
    plaintext_cbc = CBC_INPUT
    cbc_ct = tool.cbc_encrypt(plaintext_cbc, iv, tool.ascon_engine)
    print("CBC Ciphertext:", cbc_ct)
    cbc_pt = tool.cbc_decrypt(cbc_ct, iv, tool.ascon_engine)
    print("CBC Decrypted:", cbc_pt)

    print("\n======== OFB Mode Test ========")
    plaintext_ofb = OFB_INPUT
    ofb_ct = tool.ofb_encrypt(plaintext_ofb, iv, tool.ascon_engine)
    print("OFB Ciphertext:", ofb_ct)
    ofb_pt = tool.ofb_decrypt(ofb_ct, iv, tool.ascon_engine)
    print("OFB Decrypted:", ofb_pt)


#
# 6) MENU
#

def main():
    key = os.urandom(16)  # random session key
    tool = LightweightEncryptionTool(key)

    while True:
        print("\n================= MENU =================")
        print("1) (a) Demonstrate Ascon & TinyJambu encryption/decryption")
        print("2) (b) Demonstrate CBC and OFB modes using Ascon")
        print("3) (c) Extract minimal file metadata (user_id + hash) & encrypt+append to file")
        print("4) (d) Verify file integrity (compare with stored metadata) ")
        print("0) Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            test_lightweight_algorithms(tool)
        elif choice == "2":
            test_cbc_ofb(tool)
        elif choice == "3":
            file_path = input("File path: ").strip()
            if not os.path.isfile(file_path):
                print("File not found. Skipping.")
                continue
            user_id = input("Enter user ID: ").strip()
            extract_metadata(file_path, user_id, tool)

        elif choice == "4":
            file_path = input("File path: ").strip()
            if not os.path.isfile(file_path):
                print("File not found. Skipping.")
                continue
            verify_metadata(file_path, tool)

        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()