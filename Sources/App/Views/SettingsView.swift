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
        .frame(width: 700, height: 670)
    }

    // MARK: - General Tab

    private var generalTab: some View {
        Form {
            Section {
                Toggle("Launch at Login", isOn: $appState.launchAtLogin)
            } footer: {
                Text("Start \(AppIdentity.displayName) automatically when you log in to your Mac.")
            }

            Section {
                HStack(spacing: 12) {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                        .font(.title2)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Root CA Installed & Trusted")
                            .font(.subheadline)
                            .fontWeight(.medium)
                        Text("Mints ephemeral certificates locally on this Mac to inspect AI provider traffic. Nothing else is intercepted, and no data leaves your device.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 3)
            } header: {
                Text("Local Certificate Authority")
            }

            Section {
                Toggle("Auto-inject into open Terminal.app tabs on toggle", isOn: $appState.autoInjectIntoTerminal)

                CLIEnvSection()
            } header: {
                Text("Command-Line & IDE Integration")
            } footer: {
                Text("Routes terminal tools (claude code, codex, opencode, curl, python) and IDEs (VS Code, Cursor) through the proxy when protection is active.")
            }

            Section {
                Button(role: .destructive) {
                    showingUninstallConfirmation = true
                } label: {
                    Text("Remove Certificate & Reset Everything…")
                }
                .confirmationDialog(
                    "This removes \(AppIdentity.displayName)'s trusted certificate from your Keychain and resets all system proxy settings.",
                    isPresented: $showingUninstallConfirmation,
                    titleVisibility: .visible
                ) {
                    Button("Remove & Reset", role: .destructive) { appState.uninstallEverything() }
                    Button("Cancel", role: .cancel) {}
                }
            } header: {
                Text("Danger Zone")
            } footer: {
                Text("Removes the local root CA from your macOS Keychain and restores your network configuration.")
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Providers Tab

    private var providersTab: some View {
        VStack(spacing: 0) {
            List {
                Section {
                    ForEach(appState.providers) { provider in
                        HStack(spacing: 10) {
                            Toggle(isOn: Binding(
                                get: { provider.isEnabled },
                                set: { appState.setProvider(provider, enabled: $0) }
                            )) {
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack(spacing: 6) {
                                        Text(provider.providerName)
                                            .fontWeight(.medium)

                                        if provider.isCustom {
                                            Text("custom")
                                                .font(.system(size: 9.5, weight: .medium))
                                                .padding(.horizontal, 5)
                                                .padding(.vertical, 1)
                                                .background(Color.secondary.opacity(0.15))
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
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                        .padding(.vertical, 1)
                    }
                } header: {
                    Text("Intercepted AI Domains")
                } footer: {
                    Text("Traffic to these domains is routed through the local proxy. All other network traffic resolves DIRECT with zero latency.")
                }
            }
            .listStyle(.inset(alternatesRowBackgrounds: true))

            Divider()

            AddProviderRow()
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(Color(nsColor: .controlBackgroundColor).opacity(0.3))
        }
    }

    // MARK: - Detection Tab

    private var detectionTab: some View {
        VStack(spacing: 0) {
            List {
                Section("Protection Mode") {
                    Picker("When PII is detected", selection: $appState.autoRedactEnabled) {
                        Text("Auto-Redact").tag(true)
                        Text("Block Request").tag(false)
                    }
                    .pickerStyle(.segmented)

                    Text(appState.autoRedactEnabled
                        ? "Detected values are masked with [REDACTED:<category>] so prompts still complete without leaking sensitive data."
                        : "Outbound messages containing PII are rejected with an immediate HTTP 403 Forbidden response."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Section("Built-in PII Categories") {
                    ForEach(PIICategory.allCases, id: \.self) { category in
                        Toggle(isOn: Binding(
                            get: { appState.enabledCategories.contains(category) },
                            set: { isOn in
                                if isOn {
                                    appState.enabledCategories.insert(category)
                                } else {
                                    appState.enabledCategories.remove(category)
                                }
                            }
                        )) {
                            HStack(spacing: 8) {
                                Image(systemName: categoryIcon(category))
                                    .foregroundStyle(.tint)
                                    .frame(width: 18)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(category.displayName.capitalized)
                                        .fontWeight(.medium)
                                    Text(categoryDescription(category))
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }

                Section("Custom Rules") {
                    if appState.customRules.isEmpty {
                        Text("No custom rules yet. Add keyword or regex filters below.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(appState.customRules) { rule in
                        HStack {
                            Toggle(isOn: Binding(
                                get: { rule.isEnabled },
                                set: { appState.setCustomRule(rule, enabled: $0) }
                            )) {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(rule.label)
                                        .fontWeight(.medium)
                                    Text(rule.isRegex ? "regex: \(rule.pattern)" : "contains: \"\(rule.pattern)\"")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            Button {
                                appState.removeCustomRule(rule)
                            } label: {
                                Image(systemName: "trash")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }

                Section("Diagnostics") {
                    Toggle("Log raw request bodies that trigger a block", isOn: Binding(
                        get: { appState.debugLogEnabled },
                        set: { appState.debugLogEnabled = $0 }
                    ))

                    Text("Appends blocked payloads to a secure local file (0600 permissions). Use only to diagnose false positives.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)

                    HStack(spacing: 8) {
                        Button("Reveal in Finder") { appState.revealDebugLogInFinder() }
                        Button("Copy Log") { _ = appState.copyDebugLogToPasteboard() }
                        Button("Clear") { appState.clearDebugLog() }
                    }
                    .controlSize(.small)
                }
            }
            .listStyle(.inset(alternatesRowBackgrounds: true))

            Divider()

            AddCustomRuleRow()
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(Color(nsColor: .controlBackgroundColor).opacity(0.3))
        }
    }

    private func categoryIcon(_ category: PIICategory) -> String {
        switch category {
        case .email: return "envelope.fill"
        case .phoneNumber: return "phone.fill"
        case .ssn: return "person.text.rectangle.fill"
        case .creditCard: return "creditcard.fill"
        case .awsKey: return "cloud.fill"
        case .genericApiKey: return "key.fill"
        case .ipv4Address: return "network"
        case .envSecret: return "lock.shield.fill"
        case .envFile: return "doc.text.fill"
        }
    }

    private func categoryDescription(_ category: PIICategory) -> String {
        switch category {
        case .email: return "Personal and business email addresses"
        case .phoneNumber: return "US and international phone formats"
        case .ssn: return "Social Security Numbers (###-##-####)"
        case .creditCard: return "Visa, Mastercard, Amex, Discover with Luhn validation"
        case .awsKey: return "AWS Access Key IDs (AKIA...)"
        case .genericApiKey: return "OpenAI, Anthropic, Stripe, GitHub, and Slack keys"
        case .ipv4Address: return "Public and private IPv4 network addresses"
        case .envSecret: return "SECRET=, TOKEN=, and PASSWORD= key-value pairs"
        case .envFile: return "Bulk .env configuration file paste detections"
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
            Text("Add Intercepted Domain").font(.caption).fontWeight(.medium).foregroundStyle(.secondary)
            HStack(spacing: 8) {
                TextField("Domain (e.g. api.mistral.ai)", text: $host)
                    .textFieldStyle(.roundedBorder)
                TextField("Provider Name", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 150)
                Button("Add Domain") {
                    if appState.addProvider(host: host, name: name) {
                        host = ""
                        name = ""
                        errorMessage = nil
                    } else {
                        errorMessage = "Domain is already in the list or invalid."
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
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
            Text("Add Custom Rule").font(.caption).fontWeight(.medium).foregroundStyle(.secondary)
            HStack(spacing: 8) {
                TextField("Rule Label", text: $label)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 140)
                TextField(isRegex ? "Regular Expression" : "Keyword or Phrase", text: $pattern)
                    .textFieldStyle(.roundedBorder)
                Toggle("Regex", isOn: $isRegex)
                    .toggleStyle(.checkbox)
                Button("Add Rule") {
                    if appState.addCustomRule(label: label, pattern: pattern, isRegex: isRegex) {
                        label = ""
                        pattern = ""
                        errorMessage = nil
                    } else {
                        errorMessage = isRegex ? "Invalid regular expression pattern." : "Enter a non-empty phrase."
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
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
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Shell Startup Hook")
                        .font(.caption)
                        .fontWeight(.medium)
                        .foregroundStyle(.secondary)
                    Spacer()
                    if didCopy {
                        Label("Copied", systemImage: "checkmark")
                            .font(.caption2)
                            .foregroundStyle(.green)
                    }
                }

                HStack {
                    Text(appState.cliShellSnippet)
                        .font(.system(size: 11, design: .monospaced))
                        .lineLimit(2)
                        .textSelection(.enabled)
                    Spacer()
                    Button {
                        let pb = NSPasteboard.general
                        pb.clearContents()
                        pb.setString(appState.cliShellSnippet, forType: .string)
                        didCopy = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { didCopy = false }
                    } label: {
                        Image(systemName: didCopy ? "checkmark" : "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help("Copy shell snippet")
                }
                .padding(8)
                .background(Color(nsColor: .textBackgroundColor).opacity(0.6))
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            HStack(spacing: 8) {
                Button {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(appState.cliShellSnippet, forType: .string)
                    didCopy = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { didCopy = false }
                } label: {
                    Label("Copy Snippet", systemImage: "doc.on.doc")
                }

                Button {
                    appState.revealCLIEnvFileInFinder()
                } label: {
                    Label("Reveal Env File", systemImage: "folder")
                }

                Button {
                    let urls = appState.installCLIShellIntegration()
                    statusMessage = urls.isEmpty ? "Shell profiles already configured" : "Updated: \(urls.map(\.lastPathComponent).joined(separator: ", "))"
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { statusMessage = nil }
                } label: {
                    Label("Re-apply to Shells", systemImage: "arrow.clockwise")
                }

                if appState.autoInjectIntoTerminal {
                    Button {
                        let result = TerminalInjector.injectIntoOpenTabs(shellCommand: appState.cliShellSnippet)
                        switch result {
                        case .success(let count):
                            statusMessage = count == 0 ? "No idle Terminal tabs found" : "Injected into \(count) tab\(count == 1 ? "" : "s")"
                        case .failure(let error):
                            statusMessage = error.localizedDescription
                        }
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { statusMessage = nil }
                    } label: {
                        Label("Inject Open Tabs", systemImage: "terminal")
                    }
                }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

            if let statusMessage {
                Text(statusMessage)
                    .font(.caption2)
                    .foregroundStyle(.blue)
                    .transition(.opacity)
            }
        }
        .padding(.vertical, 4)
    }
}
