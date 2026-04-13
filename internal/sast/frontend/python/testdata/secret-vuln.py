# VULNERABLE: hardcoded secrets in source code
API_KEY = "sk-live-abcdef1234567890abcdef"
DB_PASSWORD = "ProductionP@ssw0rd2024!"


def connect():
    return {"key": API_KEY, "password": DB_PASSWORD}
