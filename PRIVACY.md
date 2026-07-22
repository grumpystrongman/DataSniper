# DataSniper privacy notice

## Local-first operation

DataSniper is designed to store identity profiles, request history, confirmations, and audit records on the household's own device. The core application does not require a DataSniper cloud account and does not sell personal information.

## Information processed

Depending on what the household enters, the application may process names, addresses, email addresses, phone numbers, birth year, broker record URLs, confirmation numbers, request outcomes, and helper information. These fields are used only to prepare, track, and verify privacy requests.

## External disclosures

When a user opens or completes a broker workflow, information entered into that broker's website is governed by the broker's privacy practices. DataSniper should disclose only the minimum information required for the request. Identity-document upload always requires direct user action.

Optional breach monitoring sends each configured email address to the Have I Been Pwned API when `HIBP_API_KEY` is configured. This is disabled by default. Breach findings are encrypted and retained locally. Password exposure checks use the padded Pwned Passwords k-anonymity protocol: only the first five characters of a SHA-1 hash leave DataSniper, and neither the password nor full hash is retained.

## Browser companion

The browser companion operates only when invoked for a privacy task. It should not collect general browsing history, advertising identifiers, page contents unrelated to the active task, or credentials. It never submits forms automatically.

## Retention and deletion

Household administrators control local retention. Removing the application does not automatically erase separately stored backups. Secure deletion must include the database, local vault key, administrator file, browser extension storage, and all backup copies.

## Diagnostics

Production builds should keep access logging disabled by default. Future telemetry must be opt-in, exclude identity fields and broker page contents, and provide a visible off switch.

## Children and dependent adults

A parent, guardian, or legally authorized helper should confirm they have authority before submitting requests for another person. The product must not infer authorization solely from household membership.
