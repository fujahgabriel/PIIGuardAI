import UserNotifications

enum BlockNotifier {
    static func requestAuthorizationIfNeeded() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func notifyBlocked(providerName: String, categories: [String], detectionPreviews: [String] = []) {
        let content = UNMutableNotificationContent()
        content.title = "Blocked message to \(providerName)"
        let detail = detectionPreviews.isEmpty ? categories.joined(separator: ", ") : detectionPreviews.joined(separator: ", ")
        content.body = "Detected: " + detail
        content.sound = .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    static func notifyRedacted(providerName: String, categories: [String], detectionPreviews: [String] = []) {
        let content = UNMutableNotificationContent()
        content.title = "Redacted PII before sending to \(providerName)"
        let detail = detectionPreviews.isEmpty ? categories.joined(separator: ", ") : detectionPreviews.joined(separator: ", ")
        content.body = "Removed: " + detail
        content.sound = .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    /// Transparency for `TerminalInjector`: since it types a command into
    /// the user's terminal windows on their behalf, they should always see
    /// a clear record that it happened and why.
    static func notifyTerminalsUpdated(count: Int, enabling: Bool) {
        let content = UNMutableNotificationContent()
        content.title = enabling ? "Updated \(count) Terminal tab\(count == 1 ? "" : "s")" : "Reverted \(count) Terminal tab\(count == 1 ? "" : "s")"
        content.body = enabling
            ? "PIIGuard AI routed their AI provider traffic through protection."
            : "PIIGuard AI restored their normal (direct) network settings."
        content.sound = nil
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
