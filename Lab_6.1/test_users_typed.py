from __future__ import annotations

import os
import tempfile
import unittest

from users_typed import AuthSystem


class TestAuthSystem(unittest.TestCase):
    """Test suite for the AuthSystem SQLite authentication class."""

    # Instance attribute type annotations
    temp_dir: tempfile.TemporaryDirectory[str]
    db_path: str
    auth: AuthSystem

    def setUp(self) -> None:
        """Runs before every test: creates a fresh temporary directory

        and initializes an AuthSystem instance with a new database.
        """
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_users.db")
        self.auth = AuthSystem(self.db_path)

    def tearDown(self) -> None:
        """Runs after every test: cleanly closes the database connection

        and deletes the temporary directory and database file.
        """
        self.auth.close()
        self.temp_dir.cleanup()

    def test_default_admin_created(self) -> None:
        """Verify that the default 'admin' account is seeded with 'password123'."""
        admin_login_success: bool = self.auth.checkUser("admin", "password123")
        self.assertTrue(
            admin_login_success,
            "Default admin should authenticate successfully with 'password123'.",
        )

    def test_add_and_authenticate_new_user(self) -> None:
        """Verify that a new user can be added and subsequently authenticated."""
        # 1. Add user
        result: bool = self.auth.addUser("alice", "Wonderland#2024")
        self.assertTrue(result, "Adding a brand-new user should return True.")

        # 2. Authenticate user
        is_authenticated: bool = self.auth.checkUser(
            "alice", "Wonderland#2024"
        )
        self.assertTrue(
            is_authenticated,
            "New user should be able to authenticate with correct credentials.",
        )

    def test_duplicate_username_rejected(self) -> None:
        """Verify that attempting to register an existing username returns False."""
        # Register user initially
        initial_registration: bool = self.auth.addUser("bob", "passwordA")
        self.assertTrue(initial_registration)

        # Attempt to register the exact same username with a different password
        duplicate_result: bool = self.auth.addUser("bob", "passwordB")
        self.assertFalse(
            duplicate_result,
            "Registering a duplicate username should return False.",
        )

        # Attempt to register the pre-seeded default admin account
        admin_duplicate_result: bool = self.auth.addUser(
            "admin", "newAdminPass"
        )
        self.assertFalse(
            admin_duplicate_result,
            "Registering the pre-seeded 'admin' username should return False.",
        )

    def test_incorrect_password_fails(self) -> None:
        """Verify that providing an incorrect password returns False."""
        self.auth.addUser("charlie", "CorrectPassword1")

        # Wrong password for existing user
        wrong_pass_result: bool = self.auth.checkUser(
            "charlie", "WrongPassword2"
        )
        self.assertFalse(
            wrong_pass_result,
            "Authentication with an incorrect password must return False.",
        )

        # Wrong password for default admin
        wrong_admin_pass_result: bool = self.auth.checkUser(
            "admin", "wrong_admin_password"
        )
        self.assertFalse(
            wrong_admin_pass_result,
            "Admin authentication with an incorrect password must return False.",
        )

    def test_nonexistent_user_fails(self) -> None:
        """Verify that querying a user that does not exist returns False."""
        ghost_user_result: bool = self.auth.checkUser(
            "ghost_user", "anyPassword123"
        )
        self.assertFalse(
            ghost_user_result,
            "Authentication for a nonexistent user must return False.",
        )


if __name__ == "__main__":
    unittest.main()
