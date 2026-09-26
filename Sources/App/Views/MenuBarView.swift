import SwiftUI

struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Circle()
                    .fill(appState.isProtecting ? Color.green : Color.secondary)
                    .frame(width: 8, height: 8)
                Text(appState.isProtecting ? "Protection on" : "Protection off")
                    .font(.headline)
                Spacer()
            }

            if let error = appState.lastError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Text("Block PII to AI providers")
                Spacer()
                PillToggle(isOn: Binding(
                    get: { appState.isProtecting },
                    set: { newValue in newValue ? appState.startProtection() : appState.stopProtection() }
                ))
            }
            .opacity(appState.isBusy ? 0.5 : 1)
            .allowsHitTesting(!appState.isBusy)

            Divider()

            Text("Blocked messages: \(appState.blockedCount)")
                .font(.subheadline)

            if appState.events.isEmpty {
                Text("No traffic observed yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(appState.events.prefix(8)) { event in
                            EventRow(event: event)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 160)
            }

            Divider()

            HStack(spacing: 8) {
                Button {
                    openSettings()
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    Label("Settings…", systemImage: "gearshape")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .keyboardShortcut(",", modifiers: .command)

                Button {
                    NSApp.terminate(nil)
                } label: {
                    Label("Quit \(AppIdentity.displayName)", systemImage: "power")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .keyboardShortcut("q", modifiers: .command)
            }
        }
        .padding(14)
        .frame(width: 320)
    }
}

/// A hand-drawn switch, used instead of `Toggle(...).toggleStyle(.switch)`
/// because the native switch style renders inconsistently (missing/clipped
/// knob) inside a `MenuBarExtra(.menuBarExtraStyle(.window))` popover's
/// hosting context. Drawing it ourselves guarantees identical rendering
/// every time.
private struct PillToggle: View {
    @Binding var isOn: Bool

    var body: some View {
        Capsule()
            .fill(isOn ? Color.accentColor : Color.secondary.opacity(0.35))
            .frame(width: 38, height: 22)
            .overlay(
                Circle()
                    .fill(Color.white)
                    .shadow(radius: 1)
                    .padding(2)
                    .frame(width: 22, height: 22)
                    .offset(x: isOn ? 8 : -8)
            )
            .contentShape(Rectangle())
            .onTapGesture {
                withAnimation(.easeInOut(duration: 0.15)) { isOn.toggle() }
            }
            .animation(.easeInOut(duration: 0.15), value: isOn)
    }
}

private struct EventRow: View {
    let event: TrafficEvent

    var icon: String {
        switch event.outcome {
        case .blocked: return "hand.raised.fill"
        case .allowed: return "checkmark.circle"
        case .redacted: return "eye.slash.circle"
        case .allowedUnscanned: return "questionmark.circle"
        }
    }

    var color: Color {
        switch event.outcome {
        case .blocked: return .red
        case .allowed: return .green
        case .redacted: return .blue
        case .allowedUnscanned: return .orange
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .font(.caption)
            VStack(alignment: .leading, spacing: 1) {
                Text(event.summary)
                    .font(.caption)
                Text(event.date, style: .time)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
