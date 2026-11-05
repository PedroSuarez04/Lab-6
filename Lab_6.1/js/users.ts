import * as assert from 'assert';
import * as fs from 'fs';
import * as sqlite3 from 'sqlite3';

// Activate verbose mode for sqlite3 debugging
const sqlite: sqlite3.sqlite3 = sqlite3.verbose();

/**
 * Interface representing a user record row in SQLite.
 */
interface UserRow {
  id?: number;
  username: string;
  password?: string;
}

export class AuthSystem {
  private db: sqlite3.Database;
  private ready: Promise<void>;

  /**
   * Initializes the database connection, ensures the table exists,
   * and seeds the default administrator account if absent.
   * @param dbName Database file path. Defaults to "users.db".
   */
  constructor(dbName: string = 'users.db') {
    this.db = new sqlite.Database(dbName);
    this.ready = this._init();
  }

  /**
   * Internal async setup: creates table and seeds default admin.
   */
  private async _init(): Promise<void> {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `;
    await this._run(createTableQuery);

    const adminRecord = await this._get<UserRow>(
      'SELECT 1 FROM users WHERE username = ?',
      ['admin']
    );

    if (!adminRecord) {
      await this._insertUserInternal('admin', 'password123');
    }
  }

  /**
   * Internal insertion method bypassing call logging.
   */
  private _insertUserInternal(username: string, password: string): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
      this.db.run(query, [username, password], function (err: Error | null): void {
        if (err) {
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });
  }

  /**
   * Generic promisified wrapper for db.run.
   */
  private _run(sql: string, params: unknown[] = []): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.db.run(sql, params, (err: Error | null): void => {
        if (err) return reject(err);
        resolve();
      });
    });
  }

  /**
   * Generic promisified wrapper for db.get.
   */
  private _get<T>(sql: string, params: unknown[] = []): Promise<T | undefined> {
    return new Promise<T | undefined>((resolve, reject) => {
      this.db.get(sql, params, (err: Error | null, row: unknown): void => {
        if (err) return reject(err);
        resolve(row as T | undefined);
      });
    });
  }

  /**
   * Attempts to register a new user in the database.
   * Logs function invocation with redacted password.
   * @returns True if registered successfully, False if username already exists.
   */
  public async addUser(username: string, password: string): Promise<boolean> {
    await this.ready;
    console.log(`[CALL] addUser(username: "${username}", password: "[REDACTED]")`);

    return new Promise<boolean>((resolve) => {
      const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
      this.db.run(query, [username, password], function (err: (Error & { code?: string }) | null): void {
        if (err) {
          // Check for SQLite UNIQUE constraint violation
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
   * Logs function invocation with redacted password.
   * @returns True if valid credentials, False otherwise.
   */
  public async checkUser(username: string, password: string): Promise<boolean> {
    await this.ready;
    console.log(`[CALL] checkUser(username: "${username}", password: "[REDACTED]")`);

    return new Promise<boolean>((resolve, reject) => {
      const query = 'SELECT 1 FROM users WHERE username = ? AND password = ?';
      this.db.get(query, [username, password], (err: Error | null, row: unknown): void => {
        if (err) return reject(err);
        resolve(Boolean(row));
      });
    });
  }

  /**
   * Cleanly closes the database connection.
   */
  public async close(): Promise<void> {
    await this.ready;
    console.log('[CALL] close()');

    return new Promise<void>((resolve, reject) => {
      this.db.close((err: Error | null): void => {
        if (err) return reject(err);
        resolve();
      });
    });
  }
}

// --- Automated Serial Test Suite ---
async function runSerialTests(): Promise<void> {
  console.log('==================================================');
  console.log(' Starting Serial Tests for AuthSystem (TypeScript)');
  console.log('==================================================\n');

  const testDbFile = 'test_users.db';
  if (fs.existsSync(testDbFile)) {
    fs.unlinkSync(testDbFile);
  }

  const auth = new AuthSystem(testDbFile);

  try {
    // Test 1: Verify pre-seeded admin account
    console.log('TEST 1: Admin account authenticates with default credentials');
    const adminValid: boolean = await auth.checkUser('admin', 'password123');
    assert.strictEqual(adminValid, true, 'Default admin credentials should be valid');
    console.log('-> PASS\n');

    // Test 2: Verify admin rejects wrong password
    console.log('TEST 2: Admin account rejects incorrect password');
    const adminInvalid: boolean = await auth.checkUser('admin', 'wrongPassword');
    assert.strictEqual(adminInvalid, false, 'Admin with wrong password should fail');
    console.log('-> PASS\n');

    // Test 3: Register a new user
    console.log('TEST 3: Add new user (alice)');
    const addAlice: boolean = await auth.addUser('alice', 'wonderlandPass#1');
    assert.strictEqual(addAlice, true, 'Adding a new unique user should return true');
    console.log('-> PASS\n');

    // Test 4: Authenticate the new user with correct password
    console.log('TEST 4: Authenticate alice with correct credentials');
    const aliceValid: boolean = await auth.checkUser('alice', 'wonderlandPass#1');
    assert.strictEqual(aliceValid, true, 'New user should authenticate with correct credentials');
    console.log('-> PASS\n');

    // Test 5: Reject incorrect password for new user
    console.log('TEST 5: Authenticate alice with incorrect password');
    const aliceInvalid: boolean = await auth.checkUser('alice', 'incorrectPass');
    assert.strictEqual(aliceInvalid, false, 'User should fail authentication with incorrect password');
    console.log('-> PASS\n');

    // Test 6: Reject duplicate username
    console.log('TEST 6: Attempt duplicate username registration');
    const duplicateAlice: boolean = await auth.addUser('alice', 'differentPassword');
    assert.strictEqual(duplicateAlice, false, 'Duplicate username registration should return false');

    const duplicateAdmin: boolean = await auth.addUser('admin', 'adminNewPassword');
    assert.strictEqual(duplicateAdmin, false, 'Registering existing admin should return false');
    console.log('-> PASS\n');

    // Test 7: Nonexistent user fails
    console.log('TEST 7: Nonexistent user fails authentication');
    const ghostUser: boolean = await auth.checkUser('nonexistent_user', 'anyPassword');
    assert.strictEqual(ghostUser, false, 'Nonexistent user should return false');
    console.log('-> PASS\n');

    console.log('==================================================');
    console.log(' All 7 Serial Tests Passed Successfully!');
    console.log('==================================================\n');
  } catch (error) {
    console.error('Test assertion failed:', error);
    process.exitCode = 1;
  } finally {
    await auth.close();
    if (fs.existsSync(testDbFile)) {
      fs.unlinkSync(testDbFile);
    }
  }
}

// Execute tests
runSerialTests();
