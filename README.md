# Aegis

**Automated Effective Guard against Information Stealers**

A Discord bot that lets server members report phishing links sent by suspected scammers. Reports are reviewed through a web dashboard, and abuse filings are automated to domain registrars, web hosts, GitHub, Netcraft, and Google Safe Browsing. Provider replies are monitored via IMAP and surfaced back to reporters through Discord DMs.

---

## Features

- `/report` — opens a modal in Discord to collect suspicious links and context
- `/status` — lets reporters check the progress of their case, including provider responses
- **Unique case IDs** (`AEGIS-XXXXXXXX`) on every report, embedded in outgoing emails so replies can be automatically correlated
- **React + FastAPI dashboard** for reviewing reports and triggering abuse actions
- **GitHub Pages detection** — resolves CNAME chains and checks against GitHub's IP range (`185.199.108.0/22`); custom phishing domains backed by GitHub Pages are automatically routed to `abuse@github.com`
- **Abuse automation** per reported link:
  - WHOIS lookup → email the domain registrar
  - IP/ASN lookup → email the hosting provider (Cloudflare, AWS, GCP, DigitalOcean, etc.)
  - Netcraft phishing report API submission (no account required)
  - Google Safe Browsing report form (pre-filled link)
  - GitHub abuse form (for direct `github.com` links)
- **Intelligence panels** per link — WHOIS data, host/ASN info, and RBL/reputation checks (URLhaus, Spamhaus DBL, SURBL; optionally Google Safe Browsing and VirusTotal)
- **IMAP monitor** — polls your abuse inbox for provider replies, stores them against the case, and DMs the original reporter
- **Internal case notes** — admins can attach timestamped notes to any case (not visible to reporters)
- **Reporter messages** — admins can set a custom message on a case that is shown to the reporter in `/status` replies and status-change notifications, without exposing the admin's identity
- **Privacy policy page** — super admin can author the policy in Markdown via the dashboard; the rendered page at `/privacy` is publicly accessible without login
- **Dry-run mode** — set `DRY_RUN=1` to log all outbound actions without sending anything; a banner appears in the dashboard

---

## Requirements

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/)
- A Discord application and bot token ([discord.com/developers](https://discord.com/developers/applications))
- An SMTP-capable email account for sending abuse reports (Gmail App Password recommended)
- An IMAP-capable inbox for receiving provider replies (can be the same account)

---

## Quick start

```bash
git clone <your-repo>
cd aegis
cp .env.example .env
```

Edit `.env` with your credentials (see [Configuration](#configuration) below), then:

```bash
docker compose up -d
```

This starts three containers:

| Container | Role |
|---|---|
| `bot` | Discord slash commands + IMAP monitor |
| `api` | FastAPI REST backend (internal, port 8000) |
| `web` | React dashboard served by nginx (default `http://localhost:5000`) |

The SQLite database is stored in a named Docker volume (`db_data`) shared between `bot` and `api`.

To view logs:

```bash
docker compose logs -f
```

To stop:

```bash
docker compose down
```

---

## Local development (without Docker)

### API

```bash
pip install -r requirements.api.txt
uvicorn api.main:app --reload
```

### Bot

```bash
pip install -r requirements.bot.txt
python run_bot.py
```

### Web (React dev server)

```bash
cd web
npm install
npm run dev        # proxies /api → http://localhost:8000
```

---

## Configuration

Copy `.env.example` to `.env` and fill in the values.

| Variable | Required | Description |
|---|---|---|
| `DISCORD_TOKEN` | ✅ | Bot token from the Discord Developer Portal |
| `WEB_SECRET_KEY` | ✅ | Random string used to sign sessions |
| `WEB_PORT` | — | Dashboard port (default `5000`) |
| `DB_PATH` | — | SQLite file path (default `scambot.db`; set to `/data/scambot.db` in Docker) |
| `SMTP_HOST` | ✅ | SMTP server for outgoing abuse emails (e.g. `smtp.gmail.com`) |
| `SMTP_PORT` | — | SMTP port (default `587`) |
| `SMTP_USER` | ✅ | SMTP login username |
| `SMTP_PASS` | ✅ | SMTP password or App Password |
| `SMTP_FROM` | — | From address (defaults to `SMTP_USER`) |
| `IMAP_HOST` | — | IMAP server for receiving provider replies (e.g. `imap.gmail.com`) |
| `IMAP_PORT` | — | IMAP port (default `993`) |
| `IMAP_USER` | — | IMAP login username |
| `IMAP_PASS` | — | IMAP password or App Password |
| `IMAP_POLL_INTERVAL` | — | Seconds between inbox polls (default `300`) |
| `DISCORD_CLIENT_ID` | ✅ | OAuth2 application client ID |
| `DISCORD_CLIENT_SECRET` | ✅ | OAuth2 application client secret |
| `DISCORD_REDIRECT_URI` | ✅ | OAuth2 callback URL (must match the app's Redirects list exactly) |
| `COOKIE_SECURE` | — | Set to `false` for local HTTP dev; must be `true` in production (default `true`) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | — | Enables GSB checks in the RBL panel (free key from Google Cloud Console) |
| `VIRUSTOTAL_API_KEY` | — | Enables VirusTotal checks in the RBL panel (free tier available) |
| `TRIAGE_API_KEY` | — | Enables EXE submission to Recorded Future Triage for sandboxing (see [tria.ge](https://tria.ge)) |
| `DRY_RUN` | — | Set to `1` to log all outbound actions without sending — a yellow banner appears in the dashboard |

### Discord OAuth2 setup

The dashboard requires Discord login. Authentication is separate from the bot token.

1. Go to [discord.com/developers](https://discord.com/developers/applications) → your application (or create a new one)
2. Under **OAuth2**, add your redirect URI to the **Redirects** list:
   - Local dev: `http://localhost:5000/api/auth/callback`
   - Production: `https://yourdomain.com/api/auth/callback`
3. Copy the **Client ID** and **Client Secret** into `DISCORD_CLIENT_ID` and `DISCORD_CLIENT_SECRET`
4. Set `DISCORD_REDIRECT_URI` to match the URI you registered
5. Set `COOKIE_SECURE=false` for local development (HTTP); leave it `true` for production (HTTPS)

### Adding the first admin

After starting the stack, bootstrap the super admin from the command line:

```bash
# Docker
docker compose exec bot python manage.py add-superadmin <discord_id> <username>

# Local dev
python manage.py add-superadmin <discord_id> <username>
```

Find your Discord ID by enabling **Developer Mode** in Discord settings (`Settings → Advanced → Developer Mode`), then right-clicking your profile and selecting **Copy User ID**.

Once the super admin is set, log in to the dashboard and use the **Admins** page (top-right nav) to add or remove other admins. The super admin cannot be removed through the UI.

### Discord bot setup

1. Go to [discord.com/developers](https://discord.com/developers/applications) → **New Application**
2. Under **Bot**, click **Add Bot** and copy the token into `DISCORD_TOKEN`
3. Under **OAuth2 → URL Generator**, select scopes: `bot` + `applications.commands`
4. Select bot permissions: `Send Messages` + `Use Slash Commands`
5. Open the generated URL to invite Aegis to your server

### Gmail setup

Enable IMAP in Gmail settings and generate an [App Password](https://myaccount.google.com/apppasswords) (requires 2FA). Use the App Password for both `SMTP_PASS` and `IMAP_PASS`. Consider creating a filter in Gmail to label and route provider replies to a dedicated folder or address.

---

## Usage

### Discord

| Command | Who | Description |
|---|---|---|
| `/report` | Any member | Opens a modal to submit suspicious links and context |
| `/status` | Reporter | Shows case status, actions taken, and provider responses |
| `/status case_id:AEGIS-XXXXXXXX` | Reporter | Full detail view for a specific case |
| `/add-admin @user` | Super admin | Grants dashboard access to a Discord member (native user picker) |
| `/remove-admin @user` | Super admin | Revokes dashboard access |

After submitting a report, the user receives an ephemeral confirmation with their `AEGIS-XXXXXXXX` case ID. If IMAP is configured and a provider replies, the reporter is automatically DM'd.

### Web dashboard

Open `http://localhost:5000` (or the configured `WEB_PORT`). The dashboard is served by nginx and proxies API requests to the FastAPI backend internally.

**Reports list** — filterable by status (`pending` / `reviewed` / `actioned` / `dismissed`)

**Report detail** — for each submitted URL:

| Button | Action |
|---|---|
| Email Registrar | WHOIS lookup → sends abuse email to registrar |
| Email Host | IP/ASN lookup → sends abuse email to hosting provider; automatically routes to `abuse@github.com` for GitHub Pages sites |
| Submit to Netcraft | Posts to Netcraft's phishing report API (no key required) |
| Report to Google | Opens pre-filled Google Safe Browsing report form |
| Report to GitHub | Opens pre-filled GitHub abuse form (shown for `github.com` links) |

**Intelligence panels** (per link) — click to load inline:

| Panel | Data |
|---|---|
| WHOIS | Registrar, dates, name servers, registrant, domain age badge |
| Host Info | IP, ASN, network, provider, abuse contact |
| RBL Check | URLhaus, Spamhaus DBL, SURBL (always); Google Safe Browsing, VirusTotal (if keys configured) |

All actions are logged per link with timestamps and outcome (`sent` / `failed` / `pending`). Provider responses appear in a dedicated section below the links once received.

**Internal notes** — free-text notes visible only to admins. Each note records the author's name and timestamp.

**Reporter message** — a single message field on each case. When set, it appears as "Message from our team" in the reporter's `/status` embed and is included in status-change DMs. The admin's identity is never shown to the reporter. Clearing the field removes it from future notifications.

**Privacy policy** — found at `/privacy` (no login required). Super admins can write and update it via the Admins page using a split-pane Markdown editor.

---

## GitHub Pages detection

A common scam pattern is registering a custom domain and pointing it at a GitHub Pages site via CNAME. Aegis detects this automatically:

1. **CNAME chain walk** — follows DNS CNAME records up to 10 hops, looking for any target ending in `.github.io`
2. **IP range fallback** — checks the resolved IP against GitHub's published Pages network `185.199.108.0/22`

When either signal fires, the link is badged in the dashboard and "Email Host" sends directly to `abuse@github.com` with the GitHub Pages identity and case reference, rather than contacting the generic hosting provider.

---

## Production deployment

Aegis ships a GitHub Actions workflow that builds Docker images and deploys to a server on every push to `main`.

### How it works

1. **Build job** — builds all three images (`bot`, `api`, `web`) and pushes them to [GitHub Container Registry (GHCR)](https://ghcr.io) using the built-in `GITHUB_TOKEN`. Layer caching is enabled per-image so only changed layers are rebuilt.
2. **Deploy job** — SSHes to your server and runs `docker compose pull && docker compose up -d --remove-orphans` with the GHCR image tags injected as environment variables.

### Required repository secrets

Configure these under **Settings → Secrets and variables → Actions** in your GitHub repository:

| Secret | Value |
|---|---|
| `DEPLOY_HOST` | Server IP or hostname |
| `DEPLOY_USER` | SSH username |
| `DEPLOY_SSH_KEY` | Private SSH key (add the public key to `~/.ssh/authorized_keys` on the server) |
| `DEPLOY_PATH` | Absolute path to the project directory on the server (e.g. `/srv/aegis`) |
| `GHCR_TOKEN` | GitHub Personal Access Token with `read:packages` scope — used by the server to pull images |

### Server setup (one-time)

```bash
# On the server
mkdir -p /srv/aegis
cd /srv/aegis
# Copy docker-compose.yml and create .env with production values
cp .env.example .env
# Edit .env — set real tokens, COOKIE_SECURE=true, WEB_BASE_URL=https://yourdomain.com, etc.
nano .env
```

After the first push to `main`, the workflow will build and deploy automatically. Subsequent pushes are incremental thanks to the build cache.

### Triggering a manual deploy

Push any commit to `main`, or re-run the latest workflow run from the **Actions** tab. There is no separate deployment branch — `main` is always deployed.

---

## Case tracking

Every report is assigned a unique case ID in the format `AEGIS-XXXXXXXX` (8 random hex characters). This ID is:

- Shown to the reporter in Discord on submission
- Embedded in the subject line of all outgoing abuse emails as `[Case AEGIS-XXXXXXXX]`
- Referenced in the email body with a request for providers to quote it in replies

The IMAP monitor scans incoming messages for this pattern. Matched replies are stored and surfaced in both the dashboard and via Discord DM to the original reporter.

---

## Project structure

```
aegis/
├── .github/
│   └── workflows/
│       └── deploy.yml       # Build → GHCR → SSH deploy on push to main
├── docker-compose.yml       # Orchestrates bot, api, and web containers
├── Dockerfile.api           # FastAPI container
├── Dockerfile.bot           # Discord bot + IMAP container
├── run_bot.py               # Bot entry point (Discord + IMAP, no web server)
├── bot.py                   # Discord slash commands (/report, /status, /add-admin, /remove-admin)
├── db.py                    # SQLite database layer
├── imap_monitor.py          # Background IMAP polling thread
├── manage.py                # CLI admin management (add-superadmin, replace-superadmin, list-admins)
├── requirements.api.txt     # Python deps for API container
├── requirements.bot.txt     # Python deps for bot container
├── abuse/
│   ├── dryrun.py            # DRY_RUN guard
│   ├── dropbox.py           # Scan URLs for Dropbox links + send abuse@dropbox.com reports
│   ├── intel.py             # WHOIS, host, and RBL/reputation intelligence
│   ├── triage.py            # Scan URLs for EXE links + submit to Recorded Future Triage
│   ├── whois_lookup.py      # WHOIS → registrar abuse email
│   ├── hosting.py           # IP/ASN detection → hosting provider email
│   ├── github.py            # GitHub Pages detection + abuse@github.com email
│   └── phishing.py          # Netcraft API + Google Safe Browsing URL
├── api/
│   ├── main.py              # FastAPI app
│   ├── deps.py              # Auth dependencies (JWT session cookie)
│   └── routers/
│       ├── auth.py          # Discord OAuth2 flow (/api/auth/login, /callback, /logout, /me)
│       ├── admins.py        # /api/admins endpoints (super admin only)
│       ├── reports.py       # /api/reports endpoints
│       ├── links.py         # /api/links endpoints (actions + intel)
│       └── privacy.py       # /api/privacy endpoints (GET public, PUT super admin only)
└── web/
    ├── Dockerfile           # Multi-stage: Vite build → nginx
    ├── nginx.conf           # Proxies /api → api:8000, serves React SPA
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.jsx
        ├── api.js           # Fetch wrappers for all API endpoints
        ├── utils.js         # Shared date/time formatting helpers
        └── components/
            ├── Navbar.jsx
            ├── LoginPage.jsx
            ├── AdminPage.jsx
            ├── PrivacyPage.jsx  # Public /privacy route (no login required)
            ├── DryRunBanner.jsx
            ├── ReportList.jsx
            ├── ReportDetail.jsx
            ├── StatusBadge.jsx
            ├── IntelPanel.jsx
            └── ActionLog.jsx
```
