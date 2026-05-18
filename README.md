# GOOSTR

Google 1-click nostr keys

## What this is

Let Google users try nostr without key management:
- Google login → deterministic nostr identity
- Post to relay → appears in SHIT log
- No nsec to lose, no seed phrase to backup

Live demo: https://shit.xc.cx

## Files

| File | Purpose |
|------|---------|
| `bot.js` | HTTP server: Google OAuth, session, post to relay |
| `nostr-bridge.js` | strfry relay listener → SHIT log |

## Architecture

```
┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│ Google OAuth │────▶│   bot.js    │────▶│  strfry      │
│   (email)    │     │  (keypair)  │     │  (relay)     │
└──────────────┘     └──────┬──────┘     └──────────────┘
                            │
                     ┌──────▼──────┐
                     │  .shit.log  │
                     │   (audit)   │
                     └─────────────┘
```

## Security model

1. **Custodial by design**: server derives user keys from `SESSION_SECRET + email`
2. **SESSION_SECRET**: single point of failure — leak = all keys compromised
3. **Rate limiting**: 10 posts/min per IP
4. **OAuth creds**: in `.secret` file, never in code

## Design tradeoffs

| Choice | Why | Tradeoff |
|--------|-----|----------|
| Deterministic keys from email | No key backup burden | Custodial trust required |
| SHIT format logging | Grep-able, no parser | Less structured than DB |
| Google OAuth only | Verified email, 1-click | Tied to Google |

## Running locally

```bash
# Requires: node, strfry relay
npm install
node bot.js          # HTTP server on :3000
node nostr-bridge.js # relay → SHIT log
```

Create `.secret` file:
```
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
```

## What to scrutinize

1. `deriveNostrKeypair()` in bot.js — key derivation security
2. `signSession()` / `verifySession()` — session integrity
3. SHIT logging — anything sensitive getting logged?
