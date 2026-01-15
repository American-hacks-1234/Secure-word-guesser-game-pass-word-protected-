#!/usr/bin/env python3
"""
Secure Wordle with password-derived HMAC key (PBKDF2).
- On first run you set a password; script stores salt + blob HMAC.
- Later runs require the password to derive the key and verify the blob.
Notes:
- This raises the bar vs. plain files, but if an attacker can edit the script they can
  still bypass checks. This protects mainly against casual tampering and stolen workspace files.
"""

import os
import hmac
import hashlib
import random
import time
import getpass
import sys
import json

# Config files
SALT_FILE = "key.salt"
BLOB_HMAC_FILE = "blob.hmac"
META_FILE = "meta.json"
TAMPER_LOG = "tamper.log"

# Game blob (obfuscated words)
OBFUSCATED_WORDS = [
    "gnrrc", "grcti", "pqogn", "qipco", "tgikv",
    "ouktr", "pgxct", "tgfke", "tgqml", "gxkcp",
]

# Game params
MAX_GUESSES = 6
WORD_LENGTH = 5
MAX_INVALID_ATTEMPTS = 10
MAX_RAW_INPUT = 1000

# PBKDF2 params
PBKDF2_ITER = 200_000
KEY_LEN = 32  # bytes

def now_ts():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def append_tamper_log(msg):
    try:
        with open(TAMPER_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{now_ts()} - {msg}\n")
    except Exception:
        pass

def compute_blob_hmac_from_list(blob_list, key_bytes):
    joined = "".join(blob_list).encode("utf-8")
    return hmac.new(key_bytes, joined, hashlib.sha256).hexdigest()

def derive_key_from_password(password, salt, iterations=PBKDF2_ITER):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=KEY_LEN)

def initialize_with_password():
    print("Initialization: create password to protect blob HMAC.")
    while True:
        pw1 = getpass.getpass("Choose a password (won't echo): ")
        if not pw1:
            print("Password cannot be empty.")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Passwords do not match. Try again.")
            continue
        break
    salt = os.urandom(16)
    key = derive_key_from_password(pw1, salt)
    mac = compute_blob_hmac_from_list(OBFUSCATED_WORDS, key)
    try:
        with open(SALT_FILE, "wb") as fh:
            fh.write(salt)
        with open(BLOB_HMAC_FILE, "w", encoding="utf-8") as fh:
            fh.write(mac)
        meta = {"created": now_ts(), "pbkdf2_iter": PBKDF2_ITER}
        with open(META_FILE, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
    except Exception as e:
        print("Failed to write initialization files:", e)
        return False
    print("Initialization complete. Keep your password secret.")
    return True

def load_salt_and_meta():
    try:
        with open(SALT_FILE, "rb") as fh:
            salt = fh.read()
        with open(META_FILE, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        return salt, meta
    except Exception as e:
        append_tamper_log(f"Failed to read salt/meta: {e}")
        return None, None

def verify_blob_with_password():
    if not os.path.exists(SALT_FILE) or not os.path.exists(BLOB_HMAC_FILE) or not os.path.exists(META_FILE):
        print("Protection files missing. Run initialization.")
        want = input("Initialize now? (y/N): ").strip().lower()
        if want == "y":
            return initialize_with_password()
        return False

    salt, meta = load_salt_and_meta()
    if salt is None:
        print("Cannot load salt/meta.")
        return False

    try:
        password = getpass.getpass("Enter password to unlock game: ")
    except Exception:
        print("Password input failed.")
        return False

    key = derive_key_from_password(password, salt, iterations=meta.get("pbkdf2_iter", PBKDF2_ITER))
    expected = None
    try:
        with open(BLOB_HMAC_FILE, "r", encoding="utf-8") as fh:
            expected = fh.read().strip()
    except Exception as e:
        append_tamper_log(f"Failed reading blob HMAC: {e}")
        print("Failed to read blob HMAC.")
        return False

    actual = compute_blob_hmac_from_list(OBFUSCATED_WORDS, key)
    if not hmac.compare_digest(actual, expected):
        append_tamper_log(f"Blob HMAC mismatch: expected={expected} actual={actual}")
        print("Tampering detected: blob HMAC mismatch or wrong password.")
        return False

    # keep the derived key for potential further use (not storing it anywhere persistent)
    return True

# ----- wordle logic (same as before) -----
def decode_obfuscated(words_blob):
    decoded = []
    for ob in words_blob:
        rev = ob[::-1]
        dec_chars = [chr(ord(ch) - 2) for ch in rev]
        decoded.append("".join(dec_chars))
    return decoded

def choose_secret_word(word_list):
    return random.choice(word_list)

def feedback_for_guess(guess, secret):
    res = ['-'] * len(guess)
    secret_chars = list(secret)
    for i, ch in enumerate(guess):
        if i < len(secret) and ch == secret[i]:
            res[i] = 'G'
            secret_chars[i] = None
    for i, ch in enumerate(guess):
        if res[i] == '-' and ch in secret_chars:
            res[i] = 'Y'
            idx = secret_chars.index(ch)
            secret_chars[idx] = None
    return ''.join(res)

def valid_guess(guess, word_list):
    if len(guess) != WORD_LENGTH:
        return False, f"Guess must be {WORD_LENGTH} letters."
    if not guess.isalpha():
        return False, "Guess must contain only letters (a-z)."
    if guess not in word_list:
        return False, "Guess not in allowed word list."
    return True, ""

def main():
    # Boot: if protection files absent, offer to initialize
    if not (os.path.exists(SALT_FILE) and os.path.exists(BLOB_HMAC_FILE) and os.path.exists(META_FILE)):
        print("Protection not initialized.")
        if not initialize_with_password():
            print("Initialization failed; exiting.")
            return

    if not verify_blob_with_password():
        print("Verification failed; exiting.")
        return

    # Proceed to play
    WORD_LIST = decode_obfuscated(OBFUSCATED_WORDS)
    for w in WORD_LIST:
        if len(w) != WORD_LENGTH:
            append_tamper_log("Decoded word length mismatch; exiting")
            print("Decoded word length mismatch. Exiting.")
            return

    secret = choose_secret_word(WORD_LIST)
    print("Welcome to Secure Wordle (password-protected).")
    print(f"Guess the {WORD_LENGTH}-letter word. You have {MAX_GUESSES} valid attempts.")
    invalid_count = 0
    seen_guesses = set()
    valid_attempts_used = 0

    while valid_attempts_used < MAX_GUESSES:
        prompt = f"Guess #{valid_attempts_used + 1}: "
        try:
            raw = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return

        if len(raw) > MAX_RAW_INPUT:
            print("Input too long. Try shorter guesses.")
            invalid_count += 1
            append_tamper_log(f"Long input detected (len={len(raw)})")
            if invalid_count >= MAX_INVALID_ATTEMPTS:
                print("Too many invalid attempts — exiting.")
                return
            continue

        guess = raw.strip().lower()
        ok, msg = valid_guess(guess, WORD_LIST)
        if not ok:
            print("Invalid guess:", msg)
            invalid_count += 1
            append_tamper_log(f"Invalid guess attempt: '{raw}' -> {msg}")
            if invalid_count >= MAX_INVALID_ATTEMPTS:
                print("Too many invalid attempts — exiting.")
                return
            continue

        if guess in seen_guesses:
            print("You already guessed that word. Try a different one.")
            continue

        seen_guesses.add(guess)
        valid_attempts_used += 1

        fb = feedback_for_guess(guess, secret)
        print(f"Feedback: {fb}   (G=right place, Y=present, -=absent)")

        if guess == secret:
            print(f"Congratulations! You guessed the word in {valid_attempts_used} tries.")
            return

    print("Out of guesses. The secret word was:", secret)
    print("Thanks for playing.")

if __name__ == "__main__":
    main()
