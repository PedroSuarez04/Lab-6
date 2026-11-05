import os
import tempfile
import unittest

from auth_system_test import AuthSystem


class TestAuthSystem(unittest.TestCase):
    """Test suite for the AuthSystem SQLite authentication class."""

    def setUp(self):
        """Runs before every test: creates a fresh temporary directory

        and initializes an AuthSystem instance with a new database.
        """
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_users.db")
        self.auth = AuthSystem(self.db_path)

    def tearDown(self):
        """Runs after every test: cleanly closes the database connection

        and deletes the temporary directory and database file.
        """
        self.auth.close()
        self.temp_dir.cleanup()

    def test_default_admin_created(self):
        """Verify that the default 'admin' account is seeded with 'password123'."""
        self.assertTrue(
            self.auth.checkUser("admin", "password123"),
            "Default admin should authenticate successfully with 'password123'.",
        )

    def test_add_and_authenticate_new_user(self):
        """Verify that a new user can be added and subsequently authenticated."""
        # 1. Add user
        result = self.auth.addUser("alice", "Wonderland#2024")
        self.assertTrue(result, "Adding a brand-new user should return True.")

        # 2. Authenticate user
        is_authenticated = self.auth.checkUser("alice", "Wonderland#2024")
        self.assertTrue(
            is_authenticated,
            "New user should be able to authenticate with correct credentials.",
        )

    def test_duplicate_username_rejected(self):
        """Verify that attempting to register an existing username returns False."""
        # Register user initially
        self.auth.addUser("bob", "passwordA")

        # Attempt to register the exact same username with a different password
        duplicate_result = self.auth.addUser("bob", "passwordB")
        self.assertFalse(
            duplicate_result,
            "Registering a duplicate username should return False.",
        )

        # Attempt to register the pre-seeded default admin account
        admin_duplicate_result = self.auth.addUser("admin", "newAdminPass")
        self.assertFalse(
            admin_duplicate_result,
            "Registering the pre-seeded 'admin' username should return False.",
        )

    def test_incorrect_password_fails(self):
        """Verify that providing an incorrect password returns False."""
        self.auth.addUser("charlie", "CorrectPassword1")

        # Wrong password for existing user
        self.assertFalse(
            self.auth.checkUser("charlie", "WrongPassword2"),
            "Authentication with an incorrect password must return False.",
        )

        # Wrong password for default admin
        self.assertFalse(
            self.auth.checkUser("admin", "wrong_admin_password"),
            "Admin authentication with an incorrect password must return False.",
        )

    def test_nonexistent_user_fails(self):
        """Verify that querying a user that does not exist returns False."""
        self.assertFalse(
            self.auth.checkUser("ghost_user", "anyPassword123"),
            "Authentication for a nonexistent user must return False.",
        )


if __name__ == "__main__":
    unittest.main()
