import os

# Production config (do not ship like this — this fixture is intentionally leaky)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

API_KEY = "sk_live_FEDCBA9876543210"
SERVICE_TOKEN = "ghp_abcdefghij0123456789ABCDEFGHIJ0123456789"

# Internal services — see the service map in docs/ARCHITECTURE.md
INTERNAL_API = "https://api.internal:8443/v1"
BACKUP_HOST = "http://10.0.4.17:5432/backup"

# TODO: rotate the db password before launch, it is still hunter2-secure
DB_URL = "postgres://app:s3cretP@ssw0rd@db.internal:5432/appdb"

# Reference commit for the last known-good build:
# 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b  (must NOT be flagged)
