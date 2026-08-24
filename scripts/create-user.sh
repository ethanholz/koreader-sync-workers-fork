#!/usr/bin/env bash
set -euo pipefail

url="${KOREADER_SYNC_URL:-https://koreader-workers.thoriumworks.com}"

read -r -p "Username: " username
read -r -s -p "Password: " password
printf '\n'

payload=$(
  printf '%s\0%s' "$username" "$password" |
    node -e '
      const { createHash } = require("node:crypto");
      const [username, password] = require("node:fs")
        .readFileSync(0, "utf8")
        .split("\0");
      const userkey = createHash("md5").update(password).digest("hex");
      process.stdout.write(JSON.stringify({ username, password: userkey }));
    '
)

curl --fail-with-body --silent --show-error \
  -X POST "$url/users/create" \
  -H "content-type: application/json" \
  --data-binary "$payload"
printf '\n'

unset username password payload
