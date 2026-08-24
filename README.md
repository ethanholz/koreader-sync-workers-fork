# KOReader Sync

<div style="display: flex; align-items: flex-start; gap: 2rem;">
  <img src="./public/logo.jpg" alt="KOReader Sync Server" width="150">
</div>

A KOReader progress sync server built for Cloudflare Workers and D1.

## Requirements

- Node.js 22 or newer
- A Cloudflare account

## Setup

```sh
npm install
npx wrangler login
npx wrangler d1 create koreader-sync
```

Copy the `database_id` printed by Wrangler into `wrangler.jsonc`, replacing `replace-with-d1-database-id`.

Create a password pepper for local development:

```sh
cp .dev.vars.example .dev.vars
```

Replace the example value in `.dev.vars`, then initialize the local database and start the Worker:

```sh
npm run db:migrate:local
npm run dev
```

The local server URL is printed by Wrangler.

## Deploy

Set the production password pepper, apply the D1 migration, and deploy:

```sh
npx wrangler secret put PASSWORD_SALT
npm run db:migrate
npm run deploy
```

Use the deployed `workers.dev` URL, or attach a custom domain in the Cloudflare dashboard.

## Connecting KOReader

1. Open a document in KOReader.
2. Go to **Settings → Progress Sync → Custom sync server**.
3. Enter the Worker URL.
4. Select **Register / Login** to create an account.
5. Test with **Push progress from this device now**.
6. Enable automatic progress syncing if desired.

## Configuration

| Binding | Default | Description |
| --- | --- | --- |
| `DB` | — | D1 database configured in `wrangler.jsonc` |
| `PASSWORD_SALT` | — | Required secret pepper used for password hashing |
| `DISABLE_USER_REGISTRATION` | `"false"` | Set to `"true"` in `wrangler.jsonc` to block registration |
| `AUTH_RATE_LIMITER` | 10/minute | Cloudflare rate-limit binding for user endpoints |

Passwords are stored using PBKDF2-HMAC-SHA256 with a random per-user salt and the `PASSWORD_SALT` secret as a pepper. Keep that secret stable: changing it invalidates existing passwords. The secure PBKDF2 work factor should be checked against your Workers plan's CPU limit before production use.

## API

### Register

- **POST** `/users/create`
- Body: `{ "username": "string", "password": "string" }`
- Responses: `201`, `403`, `409`

### Authenticate

- **GET** `/users/auth`
- Headers: `x-auth-user`, `x-auth-key`
- Responses: `200`, `401`

### Update progress

- **PUT** `/syncs/progress`
- Headers: `x-auth-user`, `x-auth-key`
- Body:

```json
{
  "document": "8b03a82761fae0ee6cd5a23700361e74",
  "progress": "/body/DocFragment[15]/body/div[65]/text()[1].41",
  "percentage": 0.2082,
  "device": "boox",
  "device_id": "197E7C6B3FD54A749C87DE9C1B05A3CE",
  "metadata": {
    "filename": "the_great_gatsby.epub",
    "title": "The Great Gatsby",
    "authors": "F. Scott Fitzgerald"
  }
}
```

`metadata` is optional. Previously stored metadata is preserved when omitted.

### Get progress

- **GET** `/syncs/progress/:document`
- Headers: `x-auth-user`, `x-auth-key`
- Responses: `200`, `404`

### List documents

- **GET** `/syncs/documents`
- Headers: `x-auth-user`, `x-auth-key`

### Health check

- **GET** `/health`

## Migrating from the Bun version

D1 can import an SQL dump made from the existing SQLite database, but existing password hashes use Bun's default Argon2id format and cannot be verified by this Worker. Users need a password reset or an explicit Argon2 compatibility migration before imported accounts can authenticate.

## Commands

```sh
npm run dev               # local Worker and D1
npm run typecheck         # TypeScript check
npm test                  # password hashing check
npm run build             # Wrangler dry-run bundle
npm run check             # typecheck, test, and build
npm run db:migrate:local  # apply local D1 migrations
npm run db:migrate        # apply production D1 migrations
npm run deploy            # deploy to Cloudflare
```
