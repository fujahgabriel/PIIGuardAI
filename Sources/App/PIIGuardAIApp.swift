import SwiftUI

@main
struct PIIGuardAIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var appState = AppState()

    init() {
        appDelegate.appState = appState
    }

    var body: some Scene {
        MenuBarExtra(AppIdentity.displayName, systemImage: appState.isProtecting ? "shield.fill" : "shield.slash") {
            MenuBarView()
                .environmentObject(appState)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(appState)
        }
    }
}
