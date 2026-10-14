# PIIGuard AI

A macOS menu bar app that blocks messages containing PII before they reach Claude, ChatGPT, Gemini, DeepSeek, and other LLM providers — from both browsers and command-line tools (IDE agents, `opencode`, `claude code`, `curl`, scripts).

<p align="center">
  <img src="assets/menubar.png" alt="PIIGuard AI Menu Bar Popover" width="280" />
  &nbsp;&nbsp;&nbsp;&nbsp;
  <img src="assets/activity.png" alt="PIIGuard AI Activity and Analytics" width="560" />
</p>

## How it works

1. **Local root CA.** On first "Turn on protection", the app generates a
   self-signed root certificate authority (P-256, via Apple's
   `swift-certificates`) and asks you (one admin-password prompt) to trust it
   in the System keychain.
2. **Scoped interception.**
   - *Browsers*: a PAC (Proxy Auto-Config) file routes *only* the known LLM
     provider domains (`claude.ai`, `api.anthropic.com`, `chatgpt.com`,
     `api.openai.com`, `api.deepseek.com`, `generativelanguage.googleapis.com`, etc. -- see
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
      and fires a macOS notification) or **auto-redacts it** (replaces sensitive
      values inline with `[REDACTED:<category>]` and seamlessly forwards the prompt
      if Auto-Redaction mode is enabled)
    - otherwise opens a normal upstream TLS connection to the real provider
      and relays the request/response through untouched
4. **Fast framed response relay & HTTP/3 bypass prevention:** Strips `Alt-Svc`
   headers to prevent browsers from upgrading to UDP 443 (QUIC), which would
   secretly bypass the TCP proxy. Uses framed HTTP/1.1 chunked and Content-Length
   streaming so pages like `chatgpt.com` and `claude.ai` load smoothly and
   instantly.
5. **Resilient state & cleanup:** Protection state is saved across restarts.
   If the app terminates, orphaned proxy settings are automatically cleaned up
   so your internet connection is never left disabled.
6. Nothing scanned or blocked is sent anywhere else -- detection is 100%
   local pattern matching, and the persisted activity log (Settings >
   Activity) stores only rule names and redacted previews, never raw PII.

## Supported Environments

PIIGuard AI protects sensitive data across three primary workflows via a dual-channel interception architecture:

### 1. Web Browsers (Native & Automatic)
* **Interception Mechanism**: macOS System Auto-Proxy pointing to a local PAC server (`http://127.0.0.1:58644/proxy.pac`).
* **Supported Browsers**: Safari, Google Chrome, Arc, Brave, Microsoft Edge, Opera. *(Firefox requires enabling "Enterprise Roots" in `about:config`)*.
* **Covered Domains**:
  * Claude (`claude.ai`)
  * ChatGPT (`chatgpt.com`, `chat.openai.com`)
  * Gemini (`gemini.google.com`)
  * Perplexity (`perplexity.ai`)
  * Grok (`grok.com`)
  * Custom domains added via **Settings > Providers**.
* **Zero Latency for Normal Browsing**: Non-AI traffic (Google, YouTube, GitHub, internal networks, banking) bypasses the proxy entirely (`DIRECT`) with no overhead or latency.
* **Seamless Trust**: The local root certificate is automatically installed into the macOS Keychain as trusted, preventing SSL warning screens.

### 2. Command-Line Tools & Terminal (Full Automation)
* **Interception Mechanism**: Standard CLI tools do not evaluate PAC files. PIIGuard AI manages standard proxy and TLS environment variables:
  * `HTTP_PROXY` / `HTTPS_PROXY` (`http://127.0.0.1:58643`)
  * `NODE_EXTRA_CA_CERTS` (Node.js runtime trust)
  * `SSL_CERT_FILE` & `REQUESTS_CA_BUNDLE` (Python `requests`, `httpx`, `aiohttp`, etc.)
  * `CURL_CA_BUNDLE` (`curl`)
* **Shell Integration**:
  * Automatically writes a managed environment file to `~/Library/Application Support/PIIGuard AI/env.sh`.
  * Integrates a source hook into `~/.zshrc`, `~/.bashrc`, and `~/.config/fish/config.fish`.
  * **Live Tab Injection**: Injects proxy variables directly into open Terminal tabs via AppleScript upon toggle—no shell restart required.
  * Reverts cleanly: When toggled OFF, writes an `unset` file so terminal sessions immediately return to direct connections.
* **Supported CLI Tools**:
  * **Claude Code CLI** (`claude`)
  * **OpenAI CLI / Codex**
  * **OpenCode / Aider** (e.g. DeepSeek, Claude, GPT models)
  * **Custom Python & Node scripts** using LangChain, LiteLLM, or direct SDKs.

<p align="center">
  <img src="assets/opencode.png" alt="OpenCode CLI Interception" width="560" />
</p>

### 3. IDEs & Coding Assistants (VS Code, Cursor, Windsurf, JetBrains)
* **Interception Mechanism**:
  * **User Session Environment**: PIIGuard executes `launchctl setenv` to export proxy and certificate environment variables across the user's macOS `launchd` session. GUI apps launched from Dock, Spotlight, or Finder inherit these settings.
  * **Integrated Terminals**: Terminals opened inside VS Code, Cursor, Windsurf, or JetBrains automatically source the shell environment and route through the proxy.
* **Covered API Endpoints**:
  * Anthropic API (`api.anthropic.com`)
  * OpenAI API (`api.openai.com`)
  * Google AI / Antigravity (`generativelanguage.googleapis.com`, `aiplatform.googleapis.com`, `antigravity.google`)
  * OpenRouter (`openrouter.ai`)
  * Mistral (`api.mistral.ai`), Cohere (`api.cohere.ai`), xAI (`api.x.ai`)
* **Extensions & Coding Agents**: AI coding assistants (e.g., Cline, Continue, Claude Code extensions) executing through Node or Python runtimes route their requests through the proxy.

---

### Detection & Protection Capabilities

| Category | Patterns & Scanners |
| :--- | :--- |
| **Secrets & Credentials** | API Keys (OpenAI `sk-...`, Anthropic, GitHub `ghp_...`, Stripe `sk_live_...`, AWS `AKIA...`, Slack `xox...`), `.env` file dumps, passwords, and tokens. |
| **Personal Identifiable Info** | Email addresses, phone numbers, Social Security Numbers (SSN), Credit Cards (with Luhn checksum validation), IPv4 addresses. |
| **Custom Rules** | User-defined regex patterns and case-sensitive or insensitive keyword filters. |
| **Protection Modes** | **Block Mode**: Rejects requests with HTTP 403 Forbidden and triggers a native macOS alert.<br>**Auto-Redact Mode**: Automatically substitutes PII with `[REDACTED:<category>]` in JSON bodies (e.g., `/v1/chat/completions`, `/v1/messages`) without breaking the conversation flow. |

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
2. Click the icon, flip "Block PII to AI providers" on. The app trusts the
   local CA into your login keychain and points the PAC-based proxy at your
   active network service(s), and also writes the CLI env file + shell integration.
3. Grant the notification permission prompt (for block alerts).
4. **Browser test**: open claude.ai or chatgpt.com in a *fresh* tab and try
   sending a message that contains, e.g., a fake SSN (`123-45-6789`) or a
   made-up email address. It should come back blocked (or redacted, if
   Auto-Redact is enabled), with a macOS notification and an entry in
   Settings > Activity.
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

- **Content-Length and Chunked bodies supported.** The scanner fully supports
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
