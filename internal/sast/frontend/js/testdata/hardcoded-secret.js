const API_KEY = "sk-live-abcdef1234567890abcdef";
const DB_PASSWORD = "SuperSecretDB2024!Production";

function connect() {
  return { key: API_KEY, password: DB_PASSWORD };
}

module.exports = { connect };
