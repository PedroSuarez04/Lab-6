from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from typing import Any

from users_pbkdf2 import AuthSystem


class TestAuthSystem(unittest.TestCase):
    """Unit tests for the salted PBKDF2 SQLite AuthSystem."""

    temp_dir: tempfile.TemporaryDirectory[str]
    db_path: str
    auth: AuthSystem

    def setUp(self) -> None:
        """Creates a fresh temporary database before every test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_users.db")
        self.auth = AuthSystem(self.db_path)

    def tearDown(self) -> None:
        """Closes connection and deletes the temporary database."""
        self.auth.close()
        self.temp_dir.cleanup()

    def test_default_admin_created_and_authenticates(self) -> None:
        """Verify that the default 'admin' account is created and authenticates with 'password123'."""
        admin_login_success: bool = self.auth.checkUser("admin", "password123")
        self.assertTrue(
            admin_login_success,
            "Default admin should authenticate successfully with 'password123'.",
        )

    def test_incorrect_passwords_fail(self) -> None:
        """Verify that incorrect passwords fail for both admin and regular users."""
        self.auth.addUser("charlie", "CorrectPassword#1")

        # Admin with wrong password
        admin_wrong_pass: bool = self.auth.checkUser("admin", "wrong_admin_pass")
        self.assertFalse(
            admin_wrong_pass,
            "Admin authentication must fail with an incorrect password.",
        )

        # Regular user with wrong password
        user_wrong_pass: bool = self.auth.checkUser("charlie", "WrongPassword#2")
        self.assertFalse(
            user_wrong_pass,
            "User authentication must fail with an incorrect password.",
        )

    def test_database_does_not_contain_plaintext_passwords(self) -> None:
        """Verify that raw plaintext passwords are not stored anywhere in the database."""
        raw_user_pass: str = "MyUltraSecretPassword!99"
        self.auth.addUser("alice", raw_user_pass)

        # Inspect raw database rows directly
        raw_conn: sqlite3.Connection = sqlite3.connect(self.db_path)
        raw_cursor: sqlite3.Cursor = raw_conn.cursor()
        raw_cursor.execute("SELECT username, password FROM users")
        rows: list[tuple[Any, ...]] = raw_cursor.fetchall()
        raw_conn.close()

        usernames_found: list[str] = []

        for username, stored_password in rows:
            usernames_found.append(username)

            # Assert plain passwords do not appear in stored database text
            self.assertNotIn(
                "password123",
                stored_password,
                "The admin plaintext password must not exist in the database.",
            )
            self.assertNotIn(
                raw_user_pass,
                stored_password,
                "User plaintext passwords must not exist in the database.",
            )

            # Assert the stored value matches the format '<salt_hex>$<hash_hex>'
            parts: list[str] = stored_password.split("$")
            self.assertEqual(
                len(parts),
                2,
                "Password column should contain salt and hash separated by '$'.",
            )

            salt_hex: str = parts[0]
            hash_hex: str = parts[1]

            # 16-byte salt -> 32 hex chars; SHA-256 derived key (32 bytes) -> 64 hex chars
            self.assertEqual(len(salt_hex), 32)
            self.assertEqual(len(hash_hex), 64)

        self.assertIn("admin", usernames_found)
        self.assertIn("alice", usernames_found)

    def test_unique_salts_for_same_passwords(self) -> None:
        """Verify that identical passwords generate distinct hashes due to random salting."""
        self.auth.addUser("user1", "SamePassword123")
        self.auth.addUser("user2", "SamePassword123")

        raw_conn: sqlite3.Connection = sqlite3.connect(self.db_path)
        raw_cursor: sqlite3.Cursor = raw_conn.cursor()
        raw_cursor.execute(
            "SELECT password FROM users WHERE username IN ('user1', 'user2')"
        )
        stored_entries: list[tuple[Any, ...]] = raw_cursor.fetchall()
        raw_conn.close()

        hash_entry_1: str = stored_entries[0][0]
        hash_entry_2: str = stored_entries[1][0]

        self.assertNotEqual(
            hash_entry_1,
            hash_entry_2,
            "Two identical passwords must yield different salted hashes.",
        )

    def test_add_and_authenticate_new_user(self) -> None:
        """Verify that a newly added user can authenticate with the correct password."""
        add_result: bool = self.auth.addUser("bob", "BobsSecurePassword")
        self.assertTrue(add_result)

        auth_result: bool = self.auth.checkUser("bob", "BobsSecurePassword")
        self.assertTrue(auth_result)

    def test_duplicate_username_rejected(self) -> None:
        """Verify that duplicate registrations return False and preserve the original record."""
        self.assertTrue(self.auth.addUser("bob", "initialPass"))
        self.assertFalse(self.auth.addUser("bob", "secondPass"))
        self.assertFalse(self.auth.addUser("admin", "newAdminPass"))

        # Confirm original password still works
        self.assertTrue(self.auth.checkUser("bob", "initialPass"))
        self.assertFalse(self.auth.checkUser("bob", "secondPass"))

    def test_nonexistent_user_fails(self) -> None:
        """Verify that nonexistent users fail authentication."""
        self.assertFalse(self.auth.checkUser("ghost_user", "anyPassword123"))


if __name__ == "__main__":
    unittest.main()
