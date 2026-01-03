#!/usr/bin/env bash

# -----------------------------------------------------------------------------
# MySQL Initialization Script
# -----------------------------------------------------------------------------
# Purpose:
# This script provisions an additional database and
# grants the necessary privileges to the application user.
#
# Security Note:
# We use a temporary configuration file to inject credentials. This prevents
# the root password from appearing in the process tree (`ps aux`), which happens
# when passing passwords via command-line flags (-p).
# -----------------------------------------------------------------------------

# Execution Mode:
# -e: Exit immediately on error.
# -u: Fail if variables are undefined.
# -o pipefail: Fail if any command in a pipe chain fails.
set -euo pipefail

# Configuration:
# Allow the database name to be overridden via ENV, default to 'db'.
DB_NAME=${DB_NAME:-db}

# -----------------------------------------------------------------------------
# Secure Credential Handling
# -----------------------------------------------------------------------------

# Create a temporary file for the MySQL client configuration.
MYSQL_CNF="$(mktemp)"

# Trap Handler:
# Ensure the credential file is strictly removed upon script exit,
# regardless of success, failure, or interruption (SIGINT/SIGTERM).
trap 'rm -f "$MYSQL_CNF"' EXIT

# Permissions:
# Restrict file access immediately. Only the owner (root) may read/write.
chmod 600 "$MYSQL_CNF"

# Inject Credentials:
# Write the connection details to the temp file.
cat >"$MYSQL_CNF" <<EOF
[client]
user=root
password=${MYSQL_ROOT_PASSWORD}
host=localhost
EOF

# -----------------------------------------------------------------------------
# Database Provisioning
# -----------------------------------------------------------------------------

echo "INFO: Initializing database '${DB_NAME}'..."

# Idempotency:
# Use 'IF NOT EXISTS' to ensure the script can run multiple times safely.
# We pass the config file via --defaults-extra-file for security.
mysql --defaults-extra-file="$MYSQL_CNF" <<-EOSQL
    CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;
EOSQL

# -----------------------------------------------------------------------------
# Privilege Granting
# -----------------------------------------------------------------------------

# Only attempt to grant privileges if a specific application user is defined.
# We use ${VAR:-} syntax to check for existence without triggering 'set -u' errors.
if [[ -n "${MYSQL_USER:-}" ]]; then
    echo "INFO: Granting privileges on '${DB_NAME}' to user '${MYSQL_USER}'..."

    # Grant:
    # We restrict permissions to the specific database wildcard.
    mysql --defaults-extra-file="$MYSQL_CNF" <<-EOSQL
        GRANT ALL PRIVILEGES ON \`${DB_NAME}%\`.* TO '${MYSQL_USER}'@'%';
        FLUSH PRIVILEGES;
EOSQL
fi

# Trap will automatically clean up $MYSQL_CNF here.
