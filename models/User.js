const { db, checkIfUsersExist } = require('../db/database');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
class User {
  static findByEmail(email) {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
        if (err) {
          return reject(err);
        }
        resolve(row);
      });
    });
  }
  static findByUsername(username) {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
          return reject(err);
        }
        resolve(row);
      });
    });
  }
  static findById(id) {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
        if (err) {
          console.error('Database error in findById:', err);
          return reject(err);
        }
        resolve(row);
      });
    });
  }
  static async create(userData) {
    try {
      const hashedPassword = await bcrypt.hash(userData.password, 10);
      const userId = userData.id || uuidv4();
      return new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO users (id, username, password, email, avatar_path, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
          [userId, userData.username, hashedPassword, userData.email || null, userData.avatar_path || null, userData.role || 'user', userData.status || 'active'],
          function (err) {
            if (err) {
              console.error("DB error during user creation:", err);
              return reject(err);
            }
            console.log("User created successfully with ID:", userId);
            resolve({ id: userId, username: userData.username });
          }
        );
      });
    } catch (error) {
      console.error("Error in User.create:", error);
      throw error;
    }
  }
  static update(userId, userData) {
    const fields = [];
    const values = [];
    Object.entries(userData).forEach(([key, value]) => {
      fields.push(`${key} = ?`);
      values.push(value);
    });
    fields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(userId);
    const query = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
    return new Promise((resolve, reject) => {
      db.run(query, values, function (err) {
        if (err) {
          return reject(err);
        }
        resolve({ id: userId, ...userData });
      });
    });
  }
  static async verifyPassword(plainPassword, hashedPassword) {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  static delete(userId) {
    return new Promise((resolve, reject) => {
      db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
        if (err) {
          return reject(err);
        }
        resolve({ deleted: this.changes > 0 });
      });
    });
  }
}
module.exports = User;