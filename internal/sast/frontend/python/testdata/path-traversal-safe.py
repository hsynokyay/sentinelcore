def read_config():
    # SAFE: hardcoded filename, no user input
    filename = "config.yaml"
    with open("/etc/app/" + filename) as f:
        return f.read()
