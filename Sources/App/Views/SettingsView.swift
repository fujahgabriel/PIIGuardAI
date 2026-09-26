import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var showingUninstallConfirmation = false

    var body: some View {
        TabView {
            generalTab
                .tabItem { Label("General", systemImage: "gearshape") }
            providersTab
                .tabItem { Label("Providers", systemImage: "network") }
            detectionTab
                .tabItem { Label("Detection", systemImage: "eye.trianglebadge.exclamationmark") }
            ActivityTabView()
                .tabItem { Label("Activity", systemImage: "chart.bar.doc.horizontal") }
        }
        .frame(width: 620, height: 620)
        .padding()
    }

    private var generalTab: some View {
        Form {
            Toggle("Launch at login", isOn: $appState.launchAtLogin)

            Section("Root certificate") {
                Text("\(AppIdentity.displayName) inspects traffic to AI providers by installing a local certificate authority and routing only those providers' domains through a local proxy on this Mac. Nothing else is intercepted, and no data leaves this device.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("CLI protection (Terminal)") {
                Text("Auto-deployed when you toggle protection ON — new Terminal windows and VS Code/Cursor pick up the proxy without manual steps. Covers claude code, codex, opencode, curl, python. No data leaves the device.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                CLIEnvSection()
            }

            Section {
                Button(role: .destructive) {
                    showingUninstallConfirmation = true
                } label: {
                    Text("Remove certificate & reset")
                }
                .confirmationDialog(
                    "This removes \(AppIdentity.displayName)'s trusted certificate and turns off the proxy. Your Mac's network settings will be restored.",
                    isPresented: $showingUninstallConfirmation,
                    titleVisibility: .visible
                ) {
                    Button("Remove", role: .destructive) { appState.uninstallEverything() }
                    Button("Cancel", role: .cancel) {}
                }
            }
        }
        .padding()
    }

    private var providersTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            List {
                Section("Intercepted domains") {
                    ForEach(appState.providers) { provider in
                        HStack {
                            Toggle(isOn: Binding(
                                get: { provider.isEnabled },
                                set: { appState.setProvider(provider, enabled: $0) }
                            )) {
                                VStack(alignment: .leading) {
                                    HStack(spacing: 4) {
                                        Text(provider.providerName)
                                        if provider.isCustom {
                                            Text("custom")
                                                .font(.caption2)
                                                .padding(.horizontal, 5)
                                                .padding(.vertical, 1)
                                                .background(Color.secondary.opacity(0.2))
                                                .clipShape(Capsule())
                                        }
                                    }
                                    Text(provider.host)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            if provider.isCustom {
                                Button {
                                    appState.removeProvider(provider)
                                } label: {
                                    Image(systemName: "trash")
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
            Divider()
            AddProviderRow()
                .padding()
        }
    }

    private var detectionTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            List {
                Section("When PII is detected") {
                    Toggle("Auto-redact and send instead of blocking", isOn: $appState.autoRedactEnabled)
                    Text(appState.autoRedactEnabled
                        ? "Detected text is replaced with [REDACTED:category] and the rest of the message still goes through. Falls back to a full block for detections that can't be cleanly redacted (e.g. a bulk .env file paste)."
                        : "The whole message is blocked when it contains PII."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Section("Built-in PII categories") {
                    ForEach(PIICategory.allCases, id: \.self) { category in
                        Toggle(category.displayName.capitalized, isOn: Binding(
                            get: { appState.enabledCategories.contains(category) },
                            set: { isOn in
                                if isOn {
                                    appState.enabledCategories.insert(category)
                                } else {
                                    appState.enabledCategories.remove(category)
                                }
                            }
                        ))
                    }
                }

                Section("Custom rules") {
                    if appState.customRules.isEmpty {
                        Text("No custom rules yet. Add a keyword, phrase, or regex below to block it too.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(appState.customRules) { rule in
                        HStack {
                            Toggle(isOn: Binding(
                                get: { rule.isEnabled },
                                set: { appState.setCustomRule(rule, enabled: $0) }
                            )) {
                                VStack(alignment: .leading) {
                                    Text(rule.label)
                                    Text(rule.isRegex ? "regex: \(rule.pattern)" : "contains: \"\(rule.pattern)\"")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            Button {
                                appState.removeCustomRule(rule)
                            } label: {
                                Image(systemName: "trash")
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }

                Section("Debug — log actual bodies (false positives)") {
                    Text("OFF by default. When ON, every blocked request's full body (truncated 8k) is appended to a 0600 file. Use to diagnose why a benign message was blocked, then turn OFF and clear. File → Finder.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Toggle("Log raw bodies that triggered a block", isOn: Binding(
                        get: { appState.debugLogEnabled },
                        set: { appState.debugLogEnabled = $0 }
                    ))
                    .toggleStyle(.switch)
                    HStack(spacing: 8) {
                        Button("Reveal debug log in Finder") { appState.revealDebugLogInFinder() }
                        Button("Copy debug log") {
                            _ = appState.copyDebugLogToPasteboard()
                        }
                        .help("Copy raw bodies (may contain PII) to clipboard")
                        Button("Clear debug log") { appState.clearDebugLog() }
                        Button("Copy path") {
                            let pb = NSPasteboard.general
                            pb.clearContents()
                            pb.setString(appState.debugLogURL.path, forType: .string)
                        }
                    }
                    .font(.caption)
                    Text(appState.debugLogURL.path)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            Divider()
            AddCustomRuleRow()
                .padding()
        }
    }
}

private struct AddProviderRow: View {
    @EnvironmentObject var appState: AppState
    @State private var host = ""
    @State private var name = ""
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Add a domain to intercept").font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField("domain, e.g. internal-llm.example.com", text: $host)
                    .textFieldStyle(.roundedBorder)
                TextField("name (optional)", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 140)
                Button("Add") {
                    if appState.addProvider(host: host, name: name) {
                        host = ""
                        name = ""
                        errorMessage = nil
                    } else {
                        errorMessage = "Enter a new domain that isn't already in the list."
                    }
                }
                .disabled(host.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if let errorMessage {
                Text(errorMessage).font(.caption).foregroundStyle(.red)
            }
        }
    }
}

private struct AddCustomRuleRow: View {
    @EnvironmentObject var appState: AppState
    @State private var label = ""
    @State private var pattern = ""
    @State private var isRegex = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Add a custom rule").font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField("name (optional)", text: $label)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 140)
                TextField(isRegex ? "regular expression" : "keyword or phrase", text: $pattern)
                    .textFieldStyle(.roundedBorder)
                Toggle("Regex", isOn: $isRegex)
                    .toggleStyle(.checkbox)
                Button("Add") {
                    if appState.addCustomRule(label: label, pattern: pattern, isRegex: isRegex) {
                        label = ""
                        pattern = ""
                        errorMessage = nil
                    } else {
                        errorMessage = isRegex ? "Enter a valid, non-empty regular expression." : "Enter a non-empty keyword or phrase."
                    }
                }
                .disabled(pattern.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if let errorMessage {
                Text(errorMessage).font(.caption).foregroundStyle(.red)
            }
        }
    }
}

private struct CLIEnvSection: View {
    @EnvironmentObject var appState: AppState
    @State private var didCopy = false
    @State private var statusMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Auto-installs to ~/.zshrc, ~/.zshenv, ~/.bashrc, fish on toggle ON. Toggle OFF unsets — new shells go DIRECT. No restart needed for browsers.", systemImage: "checkmark.circle.fill")
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text(appState.cliShellSnippet)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(6)
                .background(Color.secondary.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            Text("Env file: \(appState.cliEnvFileURL.path) — also sets NODE_EXTRA_CA_CERTS for claude code.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            HStack(spacing: 8) {
                Button(didCopy ? "Copied!" : "Copy snippet") {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(appState.cliShellSnippet, forType: .string)
                    didCopy = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { didCopy = false }
                }
                Button("Reveal env file") { appState.revealCLIEnvFileInFinder() }
                Button("Re-apply now") {
                    let urls = appState.installCLIShellIntegration()
                    statusMessage = urls.isEmpty ? "Already configured" : "Updated \(urls.map(\.lastPathComponent).joined(separator: ", "))"
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { statusMessage = nil }
                }
            }
            .font(.caption)
            if let statusMessage { Text(statusMessage).font(.caption2).foregroundStyle(.secondary) }
            Text("Open a NEW Terminal after toggling — existing shells need `source \"\(appState.cliEnvFileURL.path)\"`. Verify: curl -v https://api.anthropic.com  # 403 on PII when ON")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)

            Divider().padding(.vertical, 2)

            Toggle("Auto-update open Terminal.app tabs on toggle", isOn: $appState.autoInjectIntoTerminal)
            Text("When on, toggling protection also runs the source command above in every open, idle Terminal.app tab automatically -- no need to open a new one. Busy tabs (vim, ssh, an active build) are skipped so nothing running gets interrupted. Terminal.app only -- Electron-based terminals (Hyper, and most others) don't support this kind of automation.")
                .font(.caption2)
                .foregroundStyle(.secondary)
            if appState.autoInjectIntoTerminal {
                Button("Update open Terminal tabs now") {
                    let result = TerminalInjector.injectIntoOpenTabs(shellCommand: appState.cliShellSnippet)
                    switch result {
                    case .success(let count):
                        statusMessage = count == 0 ? "No open, idle Terminal.app tabs found" : "Updated \(count) tab\(count == 1 ? "" : "s")"
                    case .failure(let error):
                        statusMessage = error.localizedDescription
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { statusMessage = nil }
                }
                .font(.caption)
            }
        }
    }
}
