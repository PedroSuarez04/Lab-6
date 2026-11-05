const sqlite3 = require('sqlite3').verbose();
const assert = require('assert');

class AuthSystem {
  /**
   * Initializes database connection, creates the users table,
   * and seeds the default administrator account if absent.
   * @param {string} dbName
   */
  constructor(dbName = 'users.db') {
    this.db = new sqlite3.Database(dbName);
    this.ready = this._init();
  }

  /**
   * Internal initialization helper.
   * Ensures the table and default admin exist.
   * @returns {Promise<void>}
   */
  async _init() {
    await this._run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);

    // Check if the default admin exists; seed if missing
    const adminRecord = await this._get(
      'SELECT 1 FROM users WHERE username = ?',
      ['admin']
    );

    if (!adminRecord) {
      await this._insertUserInternal('admin', 'password123');
    }
  }

  /**
   * Internal helper to insert a user without public-facing logging.
   * @param {string} username
   * @param {string} password
   * @returns {Promise<boolean>}
   */
  _insertUserInternal(username, password) {
    return new Promise((resolve) => {
      const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
      this.db.run(query, [username, password], function (err) {
        if (err) {
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });
  }

  /**
   * Promisified wrapper for db.run.
   * @param {string} sql
   * @param {Array} params
   * @returns {Promise<void>}
   */
  _run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  }

  /**
   * Promisified wrapper for db.get.
   * @param {string} sql
   * @param {Array} params
   * @returns {Promise<any>}
   */
  _get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });
  }

  /**
   * Registers a new user.
   * @param {string} username
   * @param {string} password
   * @returns {Promise<boolean>} True if added, False if username already exists.
   */
  async addUser(username, password) {
    await this.ready;
    console.log(`[CALL] addUser(username: "${username}", password: "[REDACTED]")`);

    return new Promise((resolve) => {
      const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
      this.db.run(query, [username, password], function (err) {
        if (err) {
          // SQLite constraint error code (2067 / SQLITE_CONSTRAINT)
          if (err.code === 'SQLITE_CONSTRAINT' || (err.message && err.message.includes('UNIQUE'))) {
            resolve(false);
          } else {
            resolve(false);
          }
        } else {
          resolve(true);
        }
      });
    });
  }

  /**
   * Verifies if a username and password match a database record.
   * @param {string} username
   * @param {string} password
   * @returns {Promise<boolean>} True if valid credentials, False otherwise.
   */
  async checkUser(username, password) {
    await this.ready;
    console.log(`[CALL] checkUser(username: "${username}", password: "[REDACTED]")`);

    return new Promise((resolve, reject) => {
      const query = 'SELECT 1 FROM users WHERE username = ? AND password = ?';
      this.db.get(query, [username, password], (err, row) => {
        if (err) return reject(err);
        resolve(Boolean(row));
      });
    });
  }

  /**
   * Cleanly closes the database connection.
   * @returns {Promise<void>}
   */
  async close() {
    await this.ready;
    console.log('[CALL] close()');

    return new Promise((resolve, reject) => {
      this.db.close((err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  }
}

// --- Automated Serial Test Suite ---
async function runSerialTests() {
  console.log('==================================================');
  console.log(' Starting Serial Tests for AuthSystem');
  console.log('==================================================\n');

  // Use a distinct database file for test runs
  const fs = require('fs');
  const testDbFile = 'test_users.db';
  if (fs.existsSync(testDbFile)) {
    fs.unlinkSync(testDbFile);
  }

  const auth = new AuthSystem(testDbFile);

  try {
    // Test 1: Verify pre-seeded admin account
    console.log('TEST 1: Admin account authenticates with default credentials');
    const adminValid = await auth.checkUser('admin', 'password123');
    assert.strictEqual(adminValid, true, 'Default admin credentials should be valid');
    console.log('-> PASS\n');

    // Test 2: Verify admin rejects wrong password
    console.log('TEST 2: Admin account rejects incorrect password');
    const adminInvalid = await auth.checkUser('admin', 'wrongPassword');
    assert.strictEqual(adminInvalid, false, 'Admin with wrong password should fail');
    console.log('-> PASS\n');

    // Test 3: Register a new user
    console.log('TEST 3: Add new user (alice)');
    const addAlice = await auth.addUser('alice', 'wonderlandPass#1');
    assert.strictEqual(addAlice, true, 'Adding a new unique user should return true');
    console.log('-> PASS\n');

    // Test 4: Authenticate the new user with correct password
    console.log('TEST 4: Authenticate alice with correct credentials');
    const aliceValid = await auth.checkUser('alice', 'wonderlandPass#1');
    assert.strictEqual(aliceValid, true, 'New user should authenticate with correct credentials');
    console.log('-> PASS\n');

    // Test 5: Reject incorrect password for new user
    console.log('TEST 5: Authenticate alice with incorrect password');
    const aliceInvalid = await auth.checkUser('alice', 'incorrectPass');
    assert.strictEqual(aliceInvalid, false, 'User should fail authentication with incorrect password');
    console.log('-> PASS\n');

    // Test 6: Reject duplicate username
    console.log('TEST 6: Attempt duplicate username registration');
    const duplicateAlice = await auth.addUser('alice', 'differentPassword');
    assert.strictEqual(duplicateAlice, false, 'Duplicate username registration should return false');

    const duplicateAdmin = await auth.addUser('admin', 'adminNewPassword');
    assert.strictEqual(duplicateAdmin, false, 'Registering existing admin should return false');
    console.log('-> PASS\n');

    // Test 7: Nonexistent user fails
    console.log('TEST 7: Nonexistent user fails authentication');
    const ghostUser = await auth.checkUser('nonexistent_user', 'anyPassword');
    assert.strictEqual(ghostUser, false, 'Nonexistent user should return false');
    console.log('-> PASS\n');

    console.log('==================================================');
    console.log(' All 7 Serial Tests Passed Successfully!');
    console.log('==================================================\n');
  } catch (error) {
    console.error('Test assertion failed:', error);
  } finally {
    await auth.close();
    // Clean up temporary test database
    if (fs.existsSync(testDbFile)) {
      fs.unlinkSync(testDbFile);
    }
  }
}

// Run tests if executed directly
if (require.main === module) {
  runSerialTests();
}

module.exports = AuthSystem;
