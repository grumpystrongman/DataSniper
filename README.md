# DataSniper Privacy Agent

A local-first personal privacy assistant that helps ordinary people find high-priority data-broker removal paths, complete requests, track company deadlines, and verify whether information was removed or resurfaced.

## Design principles

- **Simple by default:** one guided setup and one clear next action.
- **Local first:** identity information is encrypted and stored on the user’s computer.
- **Hands-off monitoring:** submitted requests receive expected completion and verification dates automatically.
- **Human approval for sensitive actions:** the agent does not submit forms, upload identity documents, accept attestations, or file complaints without the person’s involvement.
- **Accessible:** large controls, plain language, family-helper support, and no technical workflow terminology in the primary interface.

## Run locally

Python 3.11 or newer is recommended.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

The dashboard opens at `http://127.0.0.1:8787`.

## Browser companion

1. Open Chrome or Edge extension management.
2. Enable developer mode.
3. Choose **Load unpacked**.
4. Select the `browser-extension` folder.
5. Start the local DataSniper application.

The companion pairs automatically with the local service. It can open the next privacy task and fill recognized fields, but it intentionally never submits the form.

## Current MVP

- Encrypted local identity vault
- Plain-language onboarding
- State-aware starter protection plan
- Grouped PeopleConnect workflow
- California DROP task for California residents
- Deadline and verification scheduling
- Removal, no-record, waiting, denial, and resurfacing states
- Local activity history
- Browser-assisted form filling
- Pairing token restricted to the local service
- Exportable, hash-verifiable local record

## Safety boundary

DataSniper assists with administrative privacy work. It does not bypass CAPTCHAs or access controls, impersonate the user, make legal attestations, or claim that a public-page disappearance proves backend deletion.

## Development direction

The next milestones are verified broker adapters, registry synchronization, signed desktop installers, browser-store distribution, email confirmation parsing, authorized-helper workflows, and regulator-ready complaint packets.
