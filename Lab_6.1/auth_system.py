import sqlite3


class AuthSystem:
    """Class-based authentication system using SQLite."""

    def __init__(self, db_name: str = "users.db"):
        """Connects to users.db, ensures the users table exists,

        and seeds the default administrator account if absent.
        """
        # Connect to the SQLite database
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()

        # Create table if not present
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        """
        )
        self.conn.commit()

        # Seed default admin account if it does not already exist
        self.cursor.execute("SELECT 1 FROM users WHERE username = ?", ("admin",))
        if self.cursor.fetchone() is None:
            self.addUser("admin", "password123")

    def addUser(self, username: str, password: str) -> bool:
        """Attempts to register a new user in the database.

        Returns:
            bool: True if the user was successfully added,
                  False if the username is already taken.
        """
        try:
            self.cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Raised when the UNIQUE constraint on username fails
            return False

    def checkUser(self, username: str, password: str) -> bool:
        """Verifies if a matching username and password combination exists.

        Returns:
            bool: True if valid credentials, False otherwise.
        """
        self.cursor.execute(
            "SELECT 1 FROM users WHERE username = ? AND password = ?",
            (username, password),
        )
        # fetchone() returns a row tuple if found, or None if no match
        return self.cursor.fetchone() is not None

    def close(self):
        """Cleanly closes the database connection."""
        if self.conn:
            self.conn.close()


# --- Demonstration ---
if __name__ == "__main__":
    # 1. Instantiate the authentication class
    auth = AuthSystem("users.db")

    # 2. Verify authentication of the default "admin" user
    admin_auth = auth.checkUser("admin", "password123")
    print(f"Default admin login: {admin_auth}")  # Expected: True

    # 3. Add a new user and authenticate with the new credentials
    add_jane = auth.addUser("jane_doe", "secretPass456")
    print(f"Add user 'jane_doe': {add_jane}")  # Expected: True

    jane_auth = auth.checkUser("jane_doe", "secretPass456")
    print(f"Login 'jane_doe' with correct password: {jane_auth}")  # Expected: True

    # 4. Attempt to add a duplicate username to demonstrate collision handling
    dup_jane = auth.addUser("jane_doe", "differentPass789")
    print(f"Duplicate 'jane_doe' registration: {dup_jane}")  # Expected: False

    # 5. Attempt to authenticate with invalid credentials
    wrong_password = auth.checkUser("jane_doe", "wrongPassword")
    print(f"Login with incorrect password: {wrong_password}")  # Expected: False

    nonexistent_user = auth.checkUser("unknown_user", "password")
    print(f"Login with nonexistent user: {nonexistent_user}")  # Expected: False

    # 6. Close the database connection
    auth.close()
    print("Database connection closed successfully.")
