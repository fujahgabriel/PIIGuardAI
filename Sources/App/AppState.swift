import Foundation
import Combine
import AppKit

@MainActor
final class AppState: ObservableObject {
    @Published private(set) var isProtecting = false {
        didSet { publishWidgetSnapshot() }
    }
    @Published private(set) var isBusy = false
    @Published var lastError: String?
    @Published private(set) var events: [TrafficEvent] = [] {
        didSet { publishWidgetSnapshot() }
    }
    @Published var providers: [ProviderDomain]
    @Published var customRules: [CustomRule] {
        didSet { persistCustomRules(); pushDetectorUpdate() }
    }
    @Published var enabledCategories: Set<PIICategory> {
        didSet { persistCategories(); pushDetectorUpdate() }
    }
    @Published var launchAtLogin: Bool {
        didSet { try? LoginItemManager.setEnabled(launchAtLogin) }
    }
    /// When on, a message with PII gets the offending text replaced with
    /// `[REDACTED:<category>]` and is still sent, instead of being blocked
    /// outright. Falls back to blocking for matches that aren't tied to one
    /// replaceable span (e.g. a bulk ".env file" paste).
    @Published var autoRedactEnabled: Bool {
        didSet {
            UserDefaults.standard.set(autoRedactEnabled, forKey: Self.autoRedactKey)
            proxy.setAutoRedactEnabled(autoRedactEnabled)
        }
    }
    /// Opt-in, off by default: when on, toggling protection also injects the
    /// CLI env `source` command into every open, idle Terminal.app tab, so
    /// already-open terminal sessions pick up (or drop) the proxy/CA env
    /// without the user closing anything. See `TerminalInjector`.
    @Published var autoInjectIntoTerminal: Bool {
        didSet { UserDefaults.standard.set(autoInjectIntoTerminal, forKey: Self.autoInjectKey) }
    }

    var blockedCount: Int { events.filter { $0.outcome == .blocked }.count }
    var allowedCount: Int { events.filter { $0.outcome == .allowed }.count }
    var unscannedCount: Int { events.filter { $0.outcome == .allowedUnscanned }.count }
    var redactedCount: Int { events.filter { $0.outcome == .redacted }.count }

    /// Counts of each blocked category across the whole log, most-common first.
    var categoryCounts: [(name: String, count: Int)] {
        var counts: [String: Int] = [:]
        for event in events where event.outcome == .blocked {
            for category in event.matchedCategories {
                counts[category, default: 0] += 1
            }
        }
        return counts.sorted { $0.value > $1.value }.map { ($0.key, $0.value) }
    }

    /// Counts of every observed event by provider, most-active first.
    var providerCounts: [(name: String, count: Int)] {
        var counts: [String: Int] = [:]
        for event in events {
            counts[event.providerName, default: 0] += 1
        }
        return counts.sorted { $0.value > $1.value }.map { ($0.key, $0.value) }
    }

    /// Per-outcome counts per day for the last 14 days, oldest first.
    /// Per-outcome counts per day for the last `days` days, oldest first.
    func dailyCounts(days: Int) -> [(day: Date, blocked: Int, allowed: Int, unscanned: Int, redacted: Int)] {
        let calendar = Calendar.current
        let today = calendar.startOfDay(for: Date())
        let dayList = (0..<days).reversed().map { calendar.date(byAdding: .day, value: -$0, to: today)! }
        var blockedByDay: [Date: Int] = [:]
        var allowedByDay: [Date: Int] = [:]
        var unscannedByDay: [Date: Int] = [:]
        var redactedByDay: [Date: Int] = [:]
        for event in events {
            let day = calendar.startOfDay(for: event.date)
            switch event.outcome {
            case .blocked: blockedByDay[day, default: 0] += 1
            case .allowed: allowedByDay[day, default: 0] += 1
            case .allowedUnscanned: unscannedByDay[day, default: 0] += 1
            case .redacted: redactedByDay[day, default: 0] += 1
            }
        }
        return dayList.map { day in (day, blockedByDay[day] ?? 0, allowedByDay[day] ?? 0, unscannedByDay[day] ?? 0, redactedByDay[day] ?? 0) }
    }

    let proxyPort: UInt16 = 58643
    let pacServerPort: UInt16 = 58644

    private let ca = CertificateAuthority()
    private lazy var identityStore = IdentityStore(ca: ca)
    private lazy var activityStore = ActivityStore(directory: ca.appSupportDirectory)
    private lazy var debugBodyStore = DebugBodyStore(directory: ca.appSupportDirectory)
    private lazy var pacFileServer = PACFileServer(port: pacServerPort)
    private let helperClient = HelperClient()
    private lazy var proxy: MITMProxyServer = {
        let p = MITMProxyServer(port: proxyPort, identityStore: identityStore, detector: makeDetector(), providers: providers)
        p.debugBodyLogger = { [weak self] host, provider, cats, body in
            self?.debugBodyStore.log(host: host, providerName: provider, categories: cats, body: body)
        }
        return p
    }()

    private var proxyDelegateBridge: ProxyDelegateBridge?

    init() {
        self.providers = Self.loadProviders()
        self.customRules = Self.loadCustomRules()
        self.enabledCategories = Self.loadCategories()
        self.launchAtLogin = LoginItemManager.isEnabled
        self.autoRedactEnabled = UserDefaults.standard.bool(forKey: Self.autoRedactKey)
        self.autoInjectIntoTerminal = UserDefaults.standard.bool(forKey: Self.autoInjectKey)
        BlockNotifier.requestAuthorizationIfNeeded()

        let bridge = ProxyDelegateBridge { [weak self] event in
            self?.record(event, persist: true)
        }
        self.proxyDelegateBridge = bridge
        proxy.delegate = bridge
        proxy.setAutoRedactEnabled(autoRedactEnabled)

        events = Array(activityStore.loadAll().prefix(1000))
        publishWidgetSnapshot()
    }

    // MARK: - Protection lifecycle

    func startProtection() {
        guard !isProtecting else { return }
        isBusy = true
        lastError = nil
        Task {
            do {
                try await Task.detached(priority: .userInitiated) { [ca, proxy, pacFileServer, helperClient, providers = providers, proxyPort, pacServerPort, autoInjectIntoTerminal] in
                    try ca.loadOrCreate()

                    // Written to disk too, purely for reference -- the *active*
                    // config points browsers at pacFileServer's HTTP URL below,
                    // since Chromium refuses file:// PAC scripts outright.
                    let pacDiskURL = SystemProxyConfigurator.pacFileURL(appSupportDirectory: ca.appSupportDirectory)
                    let pacContent = SystemProxyConfigurator.pacScript(proxyPort: proxyPort, providers: providers)
                    try? pacContent.write(to: pacDiskURL, atomically: true, encoding: .utf8)
                    pacFileServer.updateContent(Data(pacContent.utf8))
                    try pacFileServer.start()
                    let pacServerURL = URL(string: "http://127.0.0.1:\(pacServerPort)/proxy.pac")!

                    // CLI coverage: PAC only affects browsers. Auto-deploy shell + launchctl so
                    // claude code / codex / curl in Terminal + VS Code pick up the proxy without manual steps.
                    try CLIProxyEnv.writeEnvFile(appSupportDirectory: ca.appSupportDirectory, proxyPort: proxyPort, caCertificateURL: ca.certificateFileURL)
                    _ = CLIProxyEnv.ensureShellIntegration(appSupportDirectory: ca.appSupportDirectory)
                    CLIProxyEnv.setLaunchctlEnv(proxyPort: proxyPort, caCertificateURL: ca.certificateFileURL)
                    if autoInjectIntoTerminal {
                        let snippet = CLIProxyEnv.shellSnippet(appSupportDirectory: ca.appSupportDirectory)
                        if case .success(let count) = TerminalInjector.injectIntoOpenTabs(shellCommand: snippet), count > 0 {
                            BlockNotifier.notifyTerminalsUpdated(count: count, enabling: true)
                        }
                    }

                    // CA trust goes into the login keychain directly -- no elevation
                    // needed, no interactive prompt, and re-asserted on every start
                    // since a cert *item* can persist in the keychain without actually
                    // carrying trust settings (e.g. if trust was ever stripped
                    // out-of-band while the item itself remained). See
                    // TrustStoreInstaller's doc comment for why this targets the login
                    // keychain rather than the System keychain.
                    try TrustStoreInstaller.install(certificateAt: ca.certificateFileURL)

                    do {
                        // Primary path: one-time helper install (if needed), then no
                        // more prompts for this or any future toggle for the system
                        // proxy configuration (the only remaining step that needs root).
                        try helperClient.ensureInstalled()
                        let services = try SystemProxyConfigurator.servicesToEnable()
                        for service in services {
                            try helperClient.setAutoProxy(service: service, urlString: pacServerURL.absoluteString, enabled: true)
                        }
                    } catch {
                        // Fallback: helper install was declined/failed -- fall back to
                        // one-off osascript elevation, like before the helper existed.
                        let commands = try SystemProxyConfigurator.buildEnableCommands(pacServerURL: pacServerURL)
                        if !commands.isEmpty {
                            _ = try PrivilegedRunner.run(commands)
                        }
                    }

                    try proxy.start()
                }.value
                isProtecting = true
            } catch {
                lastError = Self.describe(error)
            }
            isBusy = false
        }
    }

    func stopProtection() {
        guard isProtecting else { return }
        isBusy = true
        lastError = nil
        proxy.stop()
        pacFileServer.stop()
        // Don't break existing shells: overwrite env file with unsets and clear launchctl so new terminals go DIRECT.
        try? CLIProxyEnv.writeDisabledEnvFile(appSupportDirectory: ca.appSupportDirectory)
        CLIProxyEnv.unsetLaunchctlEnv()
        if autoInjectIntoTerminal {
            let snippet = CLIProxyEnv.shellSnippet(appSupportDirectory: ca.appSupportDirectory)
            if case .success(let count) = TerminalInjector.injectIntoOpenTabs(shellCommand: snippet), count > 0 {
                BlockNotifier.notifyTerminalsUpdated(count: count, enabling: false)
            }
        }
        Task {
            do {
                try await Task.detached(priority: .userInitiated) { [helperClient] in
                    let services = SystemProxyConfigurator.touchedServices()
                    guard !services.isEmpty else { return }
                    do {
                        for service in services {
                            try helperClient.setAutoProxy(service: service, urlString: nil, enabled: false)
                        }
                        SystemProxyConfigurator.clearTouchedServices()
                    } catch {
                        let commands = SystemProxyConfigurator.buildDisableCommands()
                        if !commands.isEmpty {
                            _ = try PrivilegedRunner.run(commands)
                        }
                    }
                }.value
            } catch {
                lastError = Self.describe(error)
            }
            isProtecting = false
            isBusy = false
        }
    }

    // MARK: - CLI env (covers claude code / codex / curl that bypass PAC)

    /// Sourceable file that exports HTTP_PROXY + NODE_EXTRA_CA_CERTS etc.
    var cliEnvFileURL: URL { CLIProxyEnv.envFileURL(appSupportDirectory: ca.appSupportDirectory) }
    var cliShellSnippet: String { CLIProxyEnv.shellSnippet(appSupportDirectory: ca.appSupportDirectory) }
    var cliExportPreview: String { CLIProxyEnv.shellExportPreview(proxyPort: proxyPort, caCertificateURL: ca.certificateFileURL) }

    /// Writes/refreshes the env file on demand (also called by startProtection).
    func refreshCLIEnvFile() {
        try? CLIProxyEnv.writeEnvFile(appSupportDirectory: ca.appSupportDirectory, proxyPort: proxyPort, caCertificateURL: ca.certificateFileURL)
    }

    func revealCLIEnvFileInFinder() {
        refreshCLIEnvFile()
        NSWorkspace.shared.activateFileViewerSelecting([cliEnvFileURL])
    }

    @discardableResult
    func installCLIShellIntegration() -> [URL] {
        refreshCLIEnvFile()
        return CLIProxyEnv.ensureShellIntegration(appSupportDirectory: ca.appSupportDirectory)
    }

    func removeCLIShellIntegration() {
        CLIProxyEnv.removeShellIntegration(appSupportDirectory: ca.appSupportDirectory)
    }

    /// Removes trust for the root CA and forgets all local key material.
    /// Leaves system proxy settings alone if protection is already stopped.
    /// Note: this leaves the privileged helper installed (it's idle and only
    /// answers XPC calls from this exact signed app, so that's harmless) --
    /// there's no clean "un-bless" API, and reinstalling it costs another
    /// admin prompt, so we just leave it for next time protection turns on.
    func uninstallEverything() {
        isBusy = true
        if isProtecting { proxy.stop(); pacFileServer.stop(); isProtecting = false }
        Task {
            do {
                try await Task.detached(priority: .userInitiated) { [helperClient] in
                    let needsUntrust = TrustStoreInstaller.isInstalled()
                    let services = SystemProxyConfigurator.touchedServices()
                    if needsUntrust {
                        try? TrustStoreInstaller.remove()
                    }
                    do {
                        try helperClient.ensureInstalled()
                        for service in services {
                            try helperClient.setAutoProxy(service: service, urlString: nil, enabled: false)
                        }
                        SystemProxyConfigurator.clearTouchedServices()
                    } catch {
                        let commands = SystemProxyConfigurator.buildDisableCommands()
                        if !commands.isEmpty {
                            _ = try PrivilegedRunner.run(commands)
                        }
                    }
                }.value
                CLIProxyEnv.removeShellIntegration(appSupportDirectory: ca.appSupportDirectory)
                CLIProxyEnv.unsetLaunchctlEnv()
                CLIProxyEnv.removeEnvFile(appSupportDirectory: ca.appSupportDirectory)
                ca.destroyLocalMaterial()
                identityStore.purgeAll()
            } catch {
                lastError = Self.describe(error)
            }
            isBusy = false
        }
    }

    // MARK: - Providers

    func setProvider(_ provider: ProviderDomain, enabled: Bool) {
        guard let index = providers.firstIndex(where: { $0.id == provider.id }) else { return }
        providers[index].isEnabled = enabled
        providersChanged()
    }

    /// Adds a user-specified domain to intercept. Rejects blank input and
    /// duplicates of an already-tracked host.
    @discardableResult
    func addProvider(host: String, name: String) -> Bool {
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmedHost.isEmpty, !providers.contains(where: { $0.host == trimmedHost }) else { return false }
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        providers.append(ProviderDomain(host: trimmedHost, providerName: trimmedName.isEmpty ? trimmedHost : trimmedName, isEnabled: true, isCustom: true))
        providersChanged()
        return true
    }

    /// Only user-added domains can be removed; built-in defaults can only be disabled.
    func removeProvider(_ provider: ProviderDomain) {
        guard provider.isCustom else { return }
        providers.removeAll { $0.id == provider.id }
        providersChanged()
    }

    private func providersChanged() {
        persistProviders()
        proxy.updateProviders(providers)
        if isProtecting {
            let pacContent = SystemProxyConfigurator.pacScript(proxyPort: proxyPort, providers: providers)
            pacFileServer.updateContent(Data(pacContent.utf8))
            let pacDiskURL = SystemProxyConfigurator.pacFileURL(appSupportDirectory: ca.appSupportDirectory)
            try? pacContent.write(to: pacDiskURL, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Custom PII rules

    @discardableResult
    func addCustomRule(label: String, pattern: String, isRegex: Bool) -> Bool {
        let trimmedLabel = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedPattern = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPattern.isEmpty else { return false }
        if isRegex, (try? NSRegularExpression(pattern: trimmedPattern)) == nil { return false }
        customRules.append(CustomRule(
            label: trimmedLabel.isEmpty ? trimmedPattern : trimmedLabel,
            pattern: trimmedPattern,
            isRegex: isRegex
        ))
        return true
    }

    func removeCustomRule(_ rule: CustomRule) {
        customRules.removeAll { $0.id == rule.id }
    }

    func setCustomRule(_ rule: CustomRule, enabled: Bool) {
        guard let index = customRules.firstIndex(where: { $0.id == rule.id }) else { return }
        customRules[index].isEnabled = enabled
    }

    private func pushDetectorUpdate() {
        proxy.updateDetector(makeDetector())
    }

    // MARK: - Debug raw body logging (opt-in, 0600, truncated 8k)
    var debugLogEnabled: Bool {
        get { debugBodyStore.isEnabled }
        set { debugBodyStore.setEnabled(newValue); objectWillChange.send() }
    }
    var debugLogURL: URL { debugBodyStore.fileURLForDisplay }
    func clearDebugLog() { debugBodyStore.clear() }
    func revealDebugLogInFinder() {
        // Ensure file exists so Finder can select it
        if !FileManager.default.fileExists(atPath: debugLogURL.path) {
            debugBodyStore.log(host: "example", providerName: "debug", categories: ["test"], body: Data("debug log created".utf8))
            // Remove the dummy immediately after creation, keep file
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [debugLogURL] in
                try? FileManager.default.removeItem(at: debugLogURL)
            }
        }
        NSWorkspace.shared.activateFileViewerSelecting([debugLogURL])
    }

    private func makeDetector() -> PIIDetector {
        var detector = PIIDetector()
        detector.enabledCategories = enabledCategories
        detector.customRules = customRules
        return detector
    }

    // MARK: - Event log

    private func record(_ event: TrafficEvent, persist: Bool) {
        events.insert(event, at: 0)
        if events.count > 1000 { events.removeLast(events.count - 1000) }
        if persist { activityStore.append(event) }
        switch event.outcome {
        case .blocked:
            BlockNotifier.notifyBlocked(providerName: event.providerName, categories: event.matchedCategories, detectionPreviews: event.detectionPreviews)
        case .redacted:
            BlockNotifier.notifyRedacted(providerName: event.providerName, categories: event.matchedCategories, detectionPreviews: event.detectionPreviews)
        case .allowed, .allowedUnscanned:
            break
        }
    }

    private func publishWidgetSnapshot() {
        let snapshot = WidgetDataSnapshot(
            protectionEnabled: isProtecting,
            updatedAt: Date(),
            requestCount: events.count,
            blockedCount: blockedCount,
            recentActivity: events.prefix(4).map { event in
                WidgetActivity(
                    id: event.id,
                    date: event.date,
                    providerName: event.providerName,
                    outcome: event.outcome.rawValue
                )
            },
            dailyActivity: dailyCounts(days: 7).map { day in
                WidgetDailyActivity(
                    day: day.day,
                    requestCount: day.blocked + day.allowed + day.unscanned + day.redacted
                )
            }
        )
        WidgetSnapshotStore.publish(snapshot)
    }

    func clearActivityLog() {
        events.removeAll()
        activityStore.clear()
    }

    func revealActivityLogInFinder() {
        NSWorkspace.shared.activateFileViewerSelecting([activityStore.fileURLForDisplay])
    }

    func copyActivityLogToPasteboard() -> Bool {
        guard let data = try? Data(contentsOf: activityStore.fileURLForDisplay),
              let text = String(data: data, encoding: .utf8) else { return false }
        let pb = NSPasteboard.general; pb.clearContents()
        pb.setString(text, forType: .string)
        return true
    }

    func copyDebugLogToPasteboard() -> Bool {
        guard let data = try? Data(contentsOf: debugBodyStore.fileURLForDisplay),
              let text = String(data: data, encoding: .utf8) else { return false }
        let pb = NSPasteboard.general; pb.clearContents()
        pb.setString(text, forType: .string)
        return true
    }

    // MARK: - Persistence

    private static let providersKey = AppIdentity.defaultsKey("providers")
    private static let categoriesKey = AppIdentity.defaultsKey("enabledCategories")
    private static let customRulesKey = AppIdentity.defaultsKey("customRules")
    private static let autoRedactKey = AppIdentity.defaultsKey("autoRedactEnabled")
    private static let autoInjectKey = AppIdentity.defaultsKey("autoInjectIntoTerminal")

    private static func loadProviders() -> [ProviderDomain] {
        guard let data = UserDefaults.standard.data(forKey: providersKey),
              let saved = try? JSONDecoder().decode([ProviderDomain].self, from: data) else {
            return DefaultProviders.all
        }
        let savedByHost = Dictionary(uniqueKeysWithValues: saved.map { ($0.host, $0) })
        let builtins = DefaultProviders.all.map { savedByHost[$0.host] ?? $0 }
        let customs = saved.filter(\.isCustom)
        return builtins + customs
    }

    private func persistProviders() {
        guard let data = try? JSONEncoder().encode(providers) else { return }
        UserDefaults.standard.set(data, forKey: Self.providersKey)
    }

    private static func loadCategories() -> Set<PIICategory> {
        guard let raw = UserDefaults.standard.stringArray(forKey: categoriesKey) else {
            return Set(PIICategory.allCases)
        }
        return Set(raw.compactMap(PIICategory.init(rawValue:)))
    }

    private func persistCategories() {
        UserDefaults.standard.set(enabledCategories.map(\.rawValue), forKey: Self.categoriesKey)
    }

    private static func loadCustomRules() -> [CustomRule] {
        guard let data = UserDefaults.standard.data(forKey: customRulesKey),
              let saved = try? JSONDecoder().decode([CustomRule].self, from: data) else {
            return []
        }
        return saved
    }

    private func persistCustomRules() {
        guard let data = try? JSONEncoder().encode(customRules) else { return }
        UserDefaults.standard.set(data, forKey: Self.customRulesKey)
    }

    private static func describe(_ error: Error) -> String {
        if let runnerError = error as? PrivilegedRunnerError {
            switch runnerError {
            case .userCancelled: return "Administrator authorization was cancelled."
            case .scriptFailed(let message): return message
            }
        }
        return error.localizedDescription
    }
}

/// NSObject-free bridge so `MITMProxyServer` (a plain class, used from
/// background threads) doesn't need to know about `@MainActor`.
private final class ProxyDelegateBridge: MITMProxyServerDelegate {
    private let handler: (TrafficEvent) -> Void
    init(handler: @escaping (TrafficEvent) -> Void) { self.handler = handler }
    func proxyServer(_ server: MITMProxyServer, didRecord event: TrafficEvent) {
        handler(event)
    }
}
