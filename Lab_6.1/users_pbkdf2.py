from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from typing import Any


class AuthSystem:
    """Class-based authentication system using SQLite and salted PBKDF2-HMAC-SHA256."""

    # Security configuration constants
    HASH_ALGORITHM: str = "sha256"
    ITERATIONS: int = 100_000
    SALT_BYTES: int = 16

    # Instance attribute type annotations
    conn: sqlite3.Connection
    cursor: sqlite3.Cursor

    def __init__(self, db_name: str = "users.db") -> None:
        """Connects to the database, ensures the users table exists,

        and seeds the default administrator account if absent.
        """
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()

        # Create table if not present
        create_table_query: str = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        """
        self.cursor.execute(create_table_query)
        self.conn.commit()

        # Seed default admin account if it does not already exist
        check_admin_query: str = "SELECT 1 FROM users WHERE username = ?"
        self.cursor.execute(check_admin_query, ("admin",))
        admin_record: tuple[Any, ...] | None = self.cursor.fetchone()

        if admin_record is None:
            self.addUser("admin", "password123")

    def _hash_password(self, password: str, salt: bytes | None = None) -> str:
        """Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.

        Returns:
            str: Salt and derived key encoded as '<salt_hex>$<derived_key_hex>'.
        """
        if salt is None:
            salt = secrets.token_bytes(self.SALT_BYTES)

        derived_key: bytes = hashlib.pbkdf2_hmac(
            hash_name=self.HASH_ALGORITHM,
            password=password.encode("utf-8"),
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return f"{salt.hex()}${derived_key.hex()}"

    def _verify_password(self, password: str, stored_entry: str) -> bool:
        """Verifies a plain password against the stored '<salt_hex>$<derived_key_hex>' string

        using constant-time comparison to prevent timing attacks.
        """
        try:
            salt_hex: str
            expected_hash_hex: str
            salt_hex, expected_hash_hex = stored_entry.split("$", 1)

            salt: bytes = bytes.fromhex(salt_hex)
            expected_key: bytes = bytes.fromhex(expected_hash_hex)

            computed_key: bytes = hashlib.pbkdf2_hmac(
                hash_name=self.HASH_ALGORITHM,
                password=password.encode("utf-8"),
                salt=salt,
                iterations=self.ITERATIONS,
            )
            return hmac.compare_digest(computed_key, expected_key)
        except (ValueError, TypeError):
            return False

    def addUser(self, username: str, password: str) -> bool:
        """Attempts to register a new user with a salted password hash.

        Returns:
            bool: True if the user was successfully added,
                  False if the username is already taken.
        """
        hashed_password_entry: str = self._hash_password(password)
        insert_query: str = (
            "INSERT INTO users (username, password) VALUES (?, ?)"
        )
        try:
            self.cursor.execute(insert_query, (username, hashed_password_entry))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Raised when the UNIQUE constraint on username fails
            return False

    def checkUser(self, username: str, password: str) -> bool:
        """Verifies if the provided credentials match an existing user.

        Returns:
            bool: True if valid credentials, False otherwise.
        """
        query: str = "SELECT password FROM users WHERE username = ?"
        self.cursor.execute(query, (username,))
        record: tuple[Any, ...] | None = self.cursor.fetchone()

        if record is None:
            return False

        stored_password_entry: str = str(record[0])
        return self._verify_password(password, stored_password_entry)

    def close(self) -> None:
        """Cleanly closes the database connection."""
        if self.conn:
            self.conn.close()


# --- Demonstration ---
if __name__ == "__main__":
    auth: AuthSystem = AuthSystem("users.db")

    # 1. Verify default admin authentication
    admin_auth: bool = auth.checkUser("admin", "password123")
    print(f"Default admin login: {admin_auth}")  # Expected: True

    # 2. Add and authenticate new user
    add_jane: bool = auth.addUser("jane_doe", "secretPass456")
    print(f"Add user 'jane_doe': {add_jane}")  # Expected: True

    jane_auth: bool = auth.checkUser("jane_doe", "secretPass456")
    print(f"Login 'jane_doe' with correct password: {jane_auth}")  # Expected: True

    # 3. Reject duplicate username
    dup_jane: bool = auth.addUser("jane_doe", "differentPass789")
    print(f"Duplicate 'jane_doe' registration: {dup_jane}")  # Expected: False

    # 4. Reject incorrect password
    wrong_password: bool = auth.checkUser("jane_doe", "wrongPassword")
    print(f"Login with incorrect password: {wrong_password}")  # Expected: False

    auth.close()
