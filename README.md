# PIIGuard AI

A macOS menu bar app that blocks messages containing PII before they reach
Claude, ChatGPT, Gemini, and other LLM providers -- from both browsers and
command-line tools (IDE agents, `curl`, scripts).

## How it works

1. **Local root CA.** On first "Turn on protection", the app generates a
   self-signed root certificate authority (P-256, via Apple's
   `swift-certificates`) and asks you (one admin-password prompt) to trust it
   in the System keychain.
2. **Scoped interception.**
   - *Browsers*: a PAC (Proxy Auto-Config) file routes *only* the known LLM
     provider domains (`claude.ai`, `api.anthropic.com`, `chatgpt.com`,
     `api.openai.com`, `generativelanguage.googleapis.com`, etc. -- see
     Providers tab) through a local proxy on `127.0.0.1`. Everything else on
     your Mac goes `DIRECT` and is never touched.
   - *CLI tools*: browsers honor the system PAC automatically, but `curl`,
     Node, Python, and most CLI HTTP clients don't. The app auto-writes a
     sourceable env file (`HTTP_PROXY`/`HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`/
     `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`REQUESTS_CA_BUNDLE` pointing at a PEM
     copy of the CA) and installs a one-line `source` into your shell rc
     files, plus sets the same vars via `launchctl` for GUI apps like VS
     Code. See the "CLI protection" section in Settings > General. Open a
     **new** terminal window after toggling -- existing shells keep whatever
     env they already exported.
3. **Local MITM proxy.** For each intercepted connection, the app terminates
   TLS using a certificate it mints on the fly for that hostname (signed by
   the root CA from step 1), reads the decrypted HTTP request, and:
   - runs it through a local, on-device PII scanner (email, phone, SSN,
     credit card w/ Luhn check, AWS keys, generic API keys/secrets, IPv4,
     `.env`-style secrets/files) plus any custom keyword/regex rules you add
   - if PII is found, **blocks it** (returns an HTTP 403 to the app/browser
     and fires a macOS notification) instead of forwarding it
   - otherwise opens a normal upstream TLS connection to the real provider
     and relays the request/response through untouched
4. Nothing scanned or blocked is sent anywhere else -- detection is 100%
   local pattern matching, and the persisted activity log (Settings >
   Activity) stores only rule names and redacted previews, never raw PII.

## Why this architecture (and not a System Extension)

A "real" macOS Content Filter / Network Extension (`NEFilterDataProvider`)
would be more robust, but requires a paid Apple Developer Program
membership, Apple's approval of the network-extension entitlement for your
Team ID, and a provisioning-profile build. This app gets the same practical
outcome (local TLS interception scoped to specific domains) using only the
standard toolchain: a local proxy + PAC file/CLI env vars + a trusted local
CA. See "Porting to a System Extension" below if you later enroll in the
Developer Program.

`Network.framework` was deliberately **not** used for the proxy's TLS layer:
it has no supported way to start a plaintext HTTP `CONNECT` exchange and
then upgrade the *same* socket to TLS ("STARTTLS"), which this proxy needs.
`Security.framework`'s `SecureTransport` (`SSLContext`) does support this,
via C read/write callbacks bound directly to the raw BSD socket, so that's
what `TLSSocket.swift` uses for both proxy legs. SecureTransport is
deprecated (Apple recommends `Network.framework`) but remains present and
functional in current macOS SDKs; if Apple removes it in a future release,
`TLSSocket.swift` is the one file that would need reworking.

### A real code signature is required, not ad-hoc

The proxy mints a fresh TLS certificate+key per intercepted hostname and
must persist that key into the Keychain as a proper "key" class item so
`SecIdentityCreateWithCertificate` can pair it with the certificate for the
TLS handshake. That persistence requires the app to be signed with a real
Team ID -- an ad-hoc signature (`CODE_SIGN_IDENTITY=-`) has no associated
keychain-access-group, so the write silently fails with
`errSecMissingEntitlement` (-34018), and every connection then fails with
`errSecItemNotFound` (-25300) when the proxy tries to find the key again.
This project is configured with `DEVELOPMENT_TEAM: NBYH83Z3X8` (a free,
personal Apple ID team -- no paid membership needed) in `project.yml`;
swap in your own team ID via `security find-identity -v -p codesigning` /
Xcode's Accounts settings if you fork this.

## Building

```sh
brew install xcodegen   # once
xcodegen generate
xcodebuild -project PIIGuardAI.xcodeproj -scheme PIIGuardAI -configuration Debug -destination 'platform=macOS' -allowProvisioningUpdates build
```

Or just open `PIIGuardAI.xcodeproj` in Xcode and hit Run. First build
resolves two Swift Package dependencies (`apple/swift-certificates`,
`apple/swift-crypto`) from GitHub, so it needs network access once, and
Xcode will need a valid Apple ID signed in under Settings > Accounts (see
above) to sign the app.

If you edit `project.yml`, re-run `xcodegen generate` before building.

## Running it for real

1. Run the app (from Xcode, or `open .../Debug/PIIGuard\ AI.app`). A shield
   icon appears in the menu bar.
2. Click the icon, flip "Block PII to AI providers" on. macOS will ask you
   to authenticate as an administrator -- this is what trusts the local CA
   and turns on the PAC-based proxy for your active network service(s), and
   also writes the CLI env file + shell integration.
3. Grant the notification permission prompt (for block alerts).
4. **Browser test**: open claude.ai or chatgpt.com in a *fresh* tab and try
   sending a message that contains, e.g., a fake SSN (`123-45-6789`) or a
   made-up email address. It should come back blocked, with a macOS
   notification and an entry in Settings > Activity.
5. **CLI test**: open a *new* terminal window (existing ones have stale env)
   and run:
   ```sh
   curl -s https://api.anthropic.com/v1/messages -H "content-type: application/json" \
     -d '{"aws_key":"AKIAIOSFODNN7EXAMPLE"}'
   ```
   should come back as a 403 from the proxy when protection is on.
6. Send an ordinary message -- it should go through normally.
7. Turn protection off (or use Settings -> "Remove certificate & reset") to
   revert your network/shell settings and untrust the CA.

## Known limitations (v1)

- **Content-Length bodies only, mostly.** The scanner fully supports
  `Content-Length` and `Transfer-Encoding: chunked` JSON request bodies.
  Compressed request bodies (`Content-Encoding: gzip`, rare for these chat
  APIs' request side) are forwarded **unscanned** and logged as such in the
  Activity tab -- they are not blocked.
- **Streaming responses aren't inspected** (nor do they need to be -- this
  tool only blocks outgoing user messages, not the model's replies).
- **Regex + custom-rule detection only.** Catches structured PII (emails,
  phone numbers, SSNs, credit cards, API keys, IPs, `.env` secrets) and
  anything you add as a custom keyword/regex rule, but not unstructured PII
  like names or physical addresses in ordinary prose unless you add a rule
  for them. No on-device NER model or cloud PII API in this v1.
- **CLI coverage depends on the tool respecting standard proxy/CA env
  vars.** Most do (curl, Python, Node, Go), but a tool that hardcodes its
  own HTTP client config or ignores `HTTPS_PROXY`/`NODE_EXTRA_CA_CERTS`
  won't be covered, and existing (already-open) terminal sessions keep
  whatever env they started with until you open a new one.
- **Per-app opt-out isn't enforced.** Something that does certificate
  pinning to a specific provider (some desktop AI apps do this) would fail
  its pinning check and stop working rather than being silently
  unprotected -- worth spot-checking if you rely on a specific desktop
  client.
- **Admin password on every toggle.** `networksetup` requires admin rights
  each time; there's no way around this without a signed privileged helper
  tool (SMJobBless / a Background Task Management registered helper).

## Porting to a real System Extension later

If you enroll in the Apple Developer Program and get the network-extension
entitlement approved, `MITMProxyServer`'s per-connection logic (the PII
scan + block/forward decision in `serveOneExchange`) is the part worth
keeping -- you'd swap `POSIXSocket`/`TLSSocket`'s raw-socket CONNECT
handling for an `NEFilterDataProvider`/`NETransparentProxyProvider` that
hands you already-established flows, and you could drop the PAC file /
CLI env var dance entirely since the system extension intercepts traffic
directly regardless of what each process's HTTP client honors.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
the full license text.
