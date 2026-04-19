# Balance Forecast — Backend

Node.js/Express REST API for [Balance Forecast](https://github.com/beanpoppa/balance-forecast-app). Handles authentication, user management, and all data persistence via SQLite.

## Running

```bash
JWT_SECRET=your-secret npm start
```

Requires Node.js 20+. The database file is created automatically at `DB_PATH` on first run.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | *(required)* | Secret for signing JWT tokens. Server exits on startup if not set. |
| `DB_PATH` | `/data/forecast.db` | SQLite database path. |
| `PORT` | `3001` | Listening port. |

## Docker

```bash
docker build -t balance-forecast-backend .
docker run -e JWT_SECRET=your-secret -v /your/data:/data -p 3001:3001 balance-forecast-backend
```

Or use the pre-built image: `beanpoppa/balance-forecast-backend:latest`

See the [main repo](https://github.com/beanpoppa/balance-forecast-app) for the full setup guide and `docker-compose.yml`.

## API endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/needs-setup` | — | Returns `{ needs_setup: bool }` |
| POST | `/api/setup` | — | Create first admin account |
| POST | `/api/login` | — | Authenticate, returns JWT (rate-limited) |
| GET | `/api/settings` | user | Get user settings |
| PUT | `/api/settings` | user | Update user settings |
| GET | `/api/items` | user | List items |
| POST | `/api/items` | user | Create item |
| PUT | `/api/items/:id` | user | Update item |
| DELETE | `/api/items/:id` | user | Delete item |
| GET | `/api/reconciled` | user | Get reconciled keys |
| POST | `/api/reconciled/toggle` | user | Toggle reconciled state |
| DELETE | `/api/reconciled` | user | Clear all reconciled |
| GET | `/api/cancelled` | user | Get cancelled keys |
| POST | `/api/cancelled/toggle` | user | Toggle cancelled state |
| GET | `/api/overrides` | user | Get amount overrides |
| POST | `/api/overrides` | user | Set an override |
| DELETE | `/api/overrides/:key` | user | Remove an override |
| POST | `/api/change-password` | user | Change own password |
| POST | `/api/factory-reset` | user | Reset own data to defaults |
| GET | `/api/users` | admin | List all users |
| POST | `/api/users` | admin | Create a user |
| DELETE | `/api/users/:id` | admin | Delete a user |
| GET | `/api/health` | — | Health check |
