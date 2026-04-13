import subprocess


def ping_health_check():
    host = "127.0.0.1"
    # SAFE: no user input, explicit argument list, shell=False
    result = subprocess.run(["ping", host], shell=False, capture_output=True, text=True)
    return result.stdout
