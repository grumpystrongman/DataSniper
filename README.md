# DataSniper Privacy Agent

A local-first privacy assistant that helps a household find high-priority data-broker removal paths, complete requests, track deadlines, and verify whether information was removed or resurfaced.

## Current release target

This branch is a **production-oriented household beta**. It is suitable for controlled use by the repository owner and trusted family members on a private computer or home network. It is not yet approved for hosting unrelated customers or exposure to the public internet.

## Design principles

- **Simple by default:** one guided setup and one clear next action.
- **Local first:** identity information is encrypted and stored on the household’s computer.
- **Hands-off monitoring:** deadlines, follow-ups, verification dates, and weekly backups are handled automatically.
- **Human approval for sensitive actions:** the agent does not submit forms, upload identity documents, accept attestations, or file complaints without the person’s involvement.
- **Accessible:** large controls, plain language, family-helper support, and no technical workflow terminology in the primary interface.
- **Safe failure:** a broken broker workflow stops and explains what the person should do rather than guessing or submitting uncertain information.

## Recommended household installation

Python 3.11 or newer is required for the developer installation:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

The first launch opens `http://127.0.0.1:8787`, asks for a household administrator password, and then starts guided identity setup.

For a containerized home-server installation:

```bash
cp .env.example .env
# Replace DATASNIPER_SESSION_SECRET with a generated random value.
docker compose up -d --build
```

The Compose configuration binds only to localhost, runs as a non-root user, drops Linux capabilities, uses a read-only application filesystem, and stores persistent household data under `./data`.

## Production protections now included

- Encrypted local identity fields and a local vault key
- Argon2-protected household administrator account
- Strict same-site sessions and optional Secure cookies
- Foreign-origin rejection for state-changing browser requests
- Login rate limiting
- Security headers and no-store responses
- Trusted-host restriction
- Automatic six-hour deadline monitoring
- Weekly consistent SQLite backups with SHA-256 checksums
- Local activity audit history
- Non-root, capability-free container deployment
- Automated tests on Python 3.11 and 3.12
- Dependency vulnerability auditing in GitHub Actions
- Documented security and privacy boundaries

## Browser companion

1. Open Chrome or Edge extension management.
2. Enable developer mode.
3. Choose **Load unpacked**.
4. Select the `browser-extension` folder.
5. Start DataSniper.

The companion pairs with the local service. It can open the next privacy task and fill recognized fields, but it intentionally never submits forms, uploads identification, completes CAPTCHAs, or accepts legal attestations.

## Household operations

The `/admin` page creates recovery backups. Backups contain encrypted identity records **and the local decryption key**, so they must be stored on encrypted media controlled by the household. A working recovery process requires both the database and vault key.

Do not expose DataSniper directly to the public internet. Remote household access should use a private VPN and HTTPS configured by someone qualified to administer the network.

## Safety boundary

DataSniper assists with administrative privacy work. It does not bypass access controls, impersonate a person, establish legal authority for a helper, guarantee discovery of every broker, or claim that disappearance from a public page proves backend deletion.

## Before selling to unrelated customers

A public commercial release still requires a signed embedded-runtime installer, signed automatic updates, browser-store publication, independent security review, product-counsel review, verified broker adapters, restore-tested migration tooling, granular delegated accounts, customer support and incident-response processes, accessibility testing with older adults, and completed product/trademark/insurance decisions. See [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md).
