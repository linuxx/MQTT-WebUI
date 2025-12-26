# MQTT Web UI

A lightweight PHP web interface for managing MQTT users, ACLs, and API keys. It provides a login-protected dashboard for users and an admin area for user/ACL management, plus an HTTP endpoint to publish to MQTT using API keys.

## Features

- User authentication with session hardening and CSRF protection
- Admin console for users, ACLs, API keys, and audit logs
- User dashboard with MQTT connection details and topic permissions
- API key management and HTTP-to-MQTT publish endpoint
- Audit logging for security-relevant actions

## Requirements

- PHP 7.4+ with extensions: `pdo_mysql`, `json`, `openssl` (recommended)
- MySQL or MariaDB
- MQTT broker (e.g., Mosquitto with the MySQL auth plugin from https://github.com/jpmens/mosquitto-auth-plug)
- One of:
  - `php-mosquitto` extension (`Mosquitto\Client`), or
  - `mosquitto_pub` CLI available on the web server

## Mosquitto auth plugin config

Recommended settings in `mosquitto.conf` (or `default.conf`) for this UI:

```
auth_opt_aclquery SELECT topic FROM tbACL WHERE username = '%s'
auth_opt_userquery SELECT password FROM tbUsers WHERE username = '%s' AND is_enabled = 1
auth_opt_superquery SELECT IFNULL(COUNT(*), 0) FROM tbUsers WHERE username = '%s' AND super = 1
auth_opt_cache_ttl 0
```

## Setup (step by step)

1) Restore the database schema

```bash
mysql -u root -p < sql/schema.sql
```

This creates the `dbMQTT` database and tables. If you need to import into an existing DB, open `sql/schema.sql` and run it in your DB tool instead.

2) Configure the application

- Copy `config/config-sample.php` to `config/config.php`.
- Update the values in `config/config.php` for your database, MQTT broker, and `APP_URL`.

3) Create the initial global admin (api_user)

The API publish endpoint needs a global admin account named `api_user` so it can publish to any topic.

- Open `genhash8.php` in a browser.
- Enter a password and click Generate.
- Copy the SQL snippet it outputs and run it in your database.

This inserts the `api_user` account and ensures it has a global `#` ACL entry.

4) Log in and create your own admin account

- Sign in as `api_user`.
- Go to the Users admin page and create a new user for yourself.
- Promote that user to admin (global) in the UI.
- Use your personal admin account for day-to-day management.

5) Verify access

- Log in with your personal admin account and confirm you can see Users, ACLs, API Keys, and Audit Logs.

## Configuration

Primary settings live in `config/config.php`:

- `DB_*`: database connection
- `MQTT_*`: MQTT broker and publish options
- `APP_URL`, `APP_ENV`, `APP_TIMEZONE`
- Session hardening (`SESSION_*`) and password policy (`PASSWORD_*`)
- API rate limits and logging settings

## Application flow

- `index.php` bootstraps the app and routes authenticated users to their dashboard.
- `includes/bootstrap.php` loads configuration, autoloads classes, initializes sessions, and sets security headers.
- `public/user/dashboard.php` shows user MQTT permissions and API keys.
- `public/admin/*` contains admin pages for users, ACLs, API keys, and audit logs.

## API: Publish to MQTT

Endpoint:

```
POST /public/api/publish.php
Headers:
  X-API-Key: <api_key>
  Content-Type: application/json
Body:
  { "topic": "devices/device1", "message": "Hello" }
```

Notes:
- If the API key is scoped to a fixed topic, the `topic` in the request is ignored.
- If the API key allows any topic, `topic` is required and is scoped under the user namespace.

## Security notes

- Change the default secrets in `config/config.php` before deploying.
- Use HTTPS and set `SESSION_SECURE` to `true` in production.
- Consider restricting access to admin routes at the network level.

## Directory structure

- `config/` application configuration
- `includes/` bootstrap and layout templates
- `public/` public web root and HTTP API endpoints
- `src/` application classes (auth, users, ACLs, API keys, logging)
- `sql/` database schema

## Development

- Logs are written to `logs/` when enabled.
- Set `APP_ENV=development` to see more detailed errors.
