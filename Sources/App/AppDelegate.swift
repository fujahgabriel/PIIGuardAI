import AppKit

/// Ensures quitting the app (Cmd+Q, Dock menu, "Quit PIIGuard AI", etc.)
/// can't leave the Mac's network configuration broken.
///
/// Without this, quitting while protection is on kills the proxy listener
/// but leaves the system PAC/proxy settings and the CLI env file pointed at
/// 127.0.0.1:58643 -- since nothing is listening there anymore, *every*
/// request to a configured provider domain (browser or CLI) starts failing,
/// not just ones containing PII. We hold termination with `.terminateLater`
/// just long enough to run the same cleanup `stopProtection()` does, then
/// let the app finish quitting.
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var appState: AppState?

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let appState, appState.isProtecting else { return .terminateNow }

        appState.stopProtection()
        Task { @MainActor in
            while appState.isProtecting || appState.isBusy {
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
