import os

# Clean config: placeholders only, values come from the environment.
API_KEY = os.environ.get("API_KEY", "example")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

# Reference commit for the last known-good build:
# 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b  (a hash, not a secret)
