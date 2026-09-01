import os

# Vulnerable: hardcoded credential literal (CWE-798) -- ships with every
# clone of this repo and can't be rotated without a code change.
DATABASE_PASSWORD = "Sup3rSecretPassw0rd!"

APP_NAME = "vulnerable_app_demo"  # Safe: not a credential.


def get_api_key():
    """Safe: the fix for DATABASE_PASSWORD above -- loaded from the
    environment, not a literal."""
    return os.environ.get("API_KEY", "")
