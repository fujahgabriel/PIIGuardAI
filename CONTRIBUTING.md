# Contributing to PIIGuard AI

Thank you for your interest in contributing to PIIGuard AI! 

PIIGuard AI is an open-source, on-device privacy guard for macOS that intercepts and protects sensitive data before it reaches AI models and LLM providers. We welcome contributions, bug reports, and suggestions from the developer community.

---

## Core Privacy Principles

Before contributing, please keep in mind our non-negotiable architectural tenets:

1. **100% On-Device**: All traffic inspection, PII scanning, and auto-redaction happen entirely locally on the user's Mac. No telemetry, third-party analytics, or external cloud reporting is ever permitted.
2. **Zero Overhead for Non-AI Traffic**: Non-AI traffic (e.g. banking, GitHub, Spotify, Google) must always resolve `DIRECT` with zero proxy latency.
3. **No Unencrypted Logging of Sensitive Data**: The activity store, debug logs, and metrics must only store sanitized tokens, redacted previews, or rule names—never raw PII.

---

## Development Prerequisites

- **macOS**: 14.0 (Sonoma) or newer.
- **Xcode**: 15.0 or newer with command-line tools installed.
- **XcodeGen**: Used to generate the Xcode project from `project.yml`.
  ```bash
  brew install xcodegen
  ```

---

## Getting Started

1. **Clone the repository**:
   ```bash
   git clone https://github.com/fujahgabriel/PIIGuardAI.git
   cd PIIGuardAI
   ```

2. **Generate the Xcode project**:
   ```bash
   xcodegen generate
   ```
   *Note: Never manually edit `PIIGuardAI.xcodeproj/project.pbxproj`. All build settings, targets, and file additions should be declared in `project.yml`.*

3. **Open the project in Xcode**:
   ```bash
   open PIIGuardAI.xcodeproj
   ```

4. **Build and Run**:
   - Select the `PIIGuardAI` scheme.
   - Choose `My Mac` as the destination.
   - Press **Cmd + R** to run.
   - On the first toggle of protection, macOS will request permission to install the local root certificate into the Keychain.

---

## Codebase Architecture

```
Sources/
├── App/
│   ├── AppState.swift          # Central ObservableObject managing state and lifecycle
│   ├── Certificates/           # Root CA generation and per-host TLS certificate minting
│   │   ├── CertificateAuthority.swift
│   │   └── IdentityStore.swift
│   ├── Models/                 # Provider domains, custom rules, and activity store
│   │   ├── ProviderDomain.swift
│   │   ├── CustomRule.swift
│   │   └── ActivityStore.swift
│   ├── PII/                    # On-device pattern detection and inline redaction
│   │   ├── PIIDetector.swift
│   │   └── PIIRule.swift
│   ├── Proxy/                  # MITM forward proxy, POSIX sockets, HTTP parser, gzip relay
│   │   ├── MITMProxyServer.swift
│   │   ├── POSIXSocket.swift
│   │   ├── TLSSocket.swift
│   │   └── GzipHelper.swift
│   ├── System/                 # PAC file server, CLI proxy env, privileged helper client
│   │   ├── PACFileServer.swift
│   │   ├── CLIProxyEnv.swift
│   │   ├── SystemProxyConfigurator.swift
│   │   └── TerminalInjector.swift
│   └── Views/                  # Native SwiftUI menu bar popover and settings windows
│       ├── MenuBarView.swift
│       ├── SettingsView.swift
│       └── ActivityTabView.swift
├── Helper/                     # Privileged helper tool for system proxy/keychain operations
├── HelperShared/               # Protocols shared between main app and privileged helper
├── SharedWidgetData/           # Data models shared with macOS desktop widget
└── WidgetExtension/            # WidgetKit desktop extension
```

---

## Common Contribution Tasks

### 1. Adding a New AI Provider

If you use an LLM provider or AI agent endpoint that isn't currently intercepted by default:

1. Open `Sources/App/Models/ProviderDomain.swift`.
2. Add the domain to `DefaultProviders.all`:
   ```swift
   ProviderDomain(host: "api.example.ai", providerName: "Example AI"),
   ```
3. Run `xcodegen generate` to ensure the project is synchronized.
4. Verify by running a test request through the proxy:
   ```bash
   curl -x http://127.0.0.1:58643 -k https://api.example.ai
   ```

### 2. Adding a New PII Detection Rule

To add detection for a new category of sensitive data:

1. Open `Sources/App/PII/PIIRule.swift`.
2. Add the category case to `PIICategory` with display metadata.
3. Define the regex pattern or algorithmic validator (e.g., Luhn checksum for payment cards).
4. Add unit test coverage in `Tests/` verifying both true positives and false positives.

### 3. Improving UI and macOS Native Design

- Follow **Apple Human Interface Guidelines (HIG)**.
- Use SwiftUI native controls (`Picker.segmented`, `.formStyle(.grouped)`, SF Symbols).
- Test in both **Light Mode** and **Dark Mode**.

---

## Testing & Verification

Before submitting a Pull Request, verify your changes compile and pass validation:

1. **Build with Debug configuration**:
   ```bash
   xcodebuild -project PIIGuardAI.xcodeproj -scheme PIIGuardAI -configuration Debug build
   ```

2. **Verify Hardened Runtime**:
   ```bash
   codesign -dvvv build/Products/Debug/PIIGuard\ AI.app 2>&1 | grep "flags="
   ```
   *(Ensure `flags=0x10000(runtime)` is present)*.

---

## Submitting a Pull Request

1. **Fork the repo** and create a descriptive branch:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. **Commit your changes**:
   - Write clear, concise commit messages.
   - Keep pull requests focused on a single feature or bug fix.
3. **Push to your fork** and submit a Pull Request to `fujahgabriel/PIIGuardAI:main`.
4. Please describe the problem your PR solves and provide testing steps or screenshots where applicable.

---

## Community & Security

If you discover a security vulnerability or bypass in the proxy inspection engine, please report it privately via GitHub Security Advisories or by contacting the maintainer directly.
