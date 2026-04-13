import os

# SAFE: secrets loaded from environment variables
API_KEY = os.environ.get("API_KEY")

# Non-secret constant is fine to hardcode
APP_NAME = "SentinelCore"


def get_config():
    return {"key": API_KEY, "app": APP_NAME}
