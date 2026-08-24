#!/usr/bin/env bash
set -euo pipefail

url="${KOREADER_SYNC_URL:-https://koreader-sync.iplaybassx28515.workers.dev}"

read -r -p "Username: " username
read -r -s -p "Password: " password
printf '\n'

payload=$(
  printf '%s\0%s' "$username" "$password" |
    node -e '
      const [username, password] = require("node:fs")
        .readFileSync(0, "utf8")
        .split("\0");
      process.stdout.write(JSON.stringify({ username, password }));
    '
)

curl --fail-with-body --silent --show-error \
  -X POST "$url/users/create" \
  -H "content-type: application/json" \
  --data-binary "$payload"
printf '\n'

unset username password payload
