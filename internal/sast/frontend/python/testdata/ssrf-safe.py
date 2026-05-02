import requests


def fetch_internal_data():
    # SAFE: hardcoded URL, no user input
    url = "https://api.internal.example.com/data"
    response = requests.get(url, timeout=10)
    return response.json()
