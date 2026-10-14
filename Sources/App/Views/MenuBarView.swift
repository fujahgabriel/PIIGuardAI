import SwiftUI

struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header Row: App Icon + Name + Native Switch
            HStack(alignment: .center, spacing: 10) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 28, height: 28)

                VStack(alignment: .leading, spacing: 1) {
                    Text(AppIdentity.displayName)
                        .font(.system(size: 13, weight: .semibold))

                    HStack(spacing: 4) {
                        Circle()
                            .fill(appState.isProtecting ? Color.green : Color.secondary.opacity(0.5))
                            .frame(width: 6, height: 6)

                        Text(appState.isBusy ? "Configuring…" : (appState.isProtecting ? "Active" : "Disabled"))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer()

                NativeSwitch(isOn: Binding(
                    get: { appState.isProtecting },
                    set: { newValue in newValue ? appState.startProtection() : appState.stopProtection() }
                ))
                .disabled(appState.isBusy)
            }

            // Error Message (if any)
            if let error = appState.lastError {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .font(.caption2)
                        .padding(.top, 1)

                    Text(error)
                        .font(.caption2)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.red.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            }

            Divider()

            // Native Segmented Control for Protection Mode
            VStack(alignment: .leading, spacing: 6) {
                Picker("", selection: $appState.autoRedactEnabled) {
                    Text("Auto-Redact").tag(true)
                    Text("Block").tag(false)
                }
                .pickerStyle(.segmented)
                .labelsHidden()

                Text(appState.autoRedactEnabled
                     ? "Silently masks PII with [REDACTED] tokens before sending."
                     : "Rejects requests containing PII with an HTTP 403 error.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Subtle Native Stats Row
            HStack(spacing: 0) {
                statColumn(label: "Redacted", count: appState.redactedCount)
                Divider().frame(height: 22)
                statColumn(label: "Blocked", count: appState.blockedCount)
                Divider().frame(height: 22)
                statColumn(label: "Allowed", count: appState.allowedCount)
            }
            .padding(.vertical, 6)
            .background(Color(nsColor: .controlBackgroundColor).opacity(0.4))
            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))

            Divider()

            // Recent Activity Section
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Recent Activity")
                        .font(.caption)
                        .fontWeight(.medium)
                        .foregroundStyle(.secondary)

                    Spacer()

                    if !appState.events.isEmpty {
                        Button("View All") {
                            openSettings()
                            NSApp.activate(ignoringOtherApps: true)
                        }
                        .font(.caption2)
                        .buttonStyle(.link)
                    }
                }

                if appState.events.isEmpty {
                    Text("No AI traffic observed yet.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.vertical, 12)
                } else {
                    VStack(spacing: 4) {
                        ForEach(appState.events.prefix(5)) { event in
                            ActivityRow(event: event)
                        }
                    }
                }
            }

            Divider()

            // Bottom Actions (Standard macOS Control Size)
            HStack {
                Button {
                    openSettings()
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    Label("Settings…", systemImage: "gearshape")
                }
                .keyboardShortcut(",", modifiers: .command)

                Spacer()

                Button {
                    NSApp.terminate(nil)
                } label: {
                    Label("Quit", systemImage: "power")
                }
                .keyboardShortcut("q", modifiers: .command)
            }
            .controlSize(.small)
        }
        .padding(12)
        .frame(width: 290)
    }

    private func statColumn(label: String, count: Int) -> some View {
        VStack(spacing: 1) {
            Text("\(count)")
                .font(.system(size: 13, weight: .semibold, design: .rounded))
            Text(label)
                .font(.system(size: 9.5))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Native-Styled Components

private struct ActivityRow: View {
    let event: TrafficEvent

    var dotColor: Color {
        switch event.outcome {
        case .blocked: return .red
        case .allowed: return .green
        case .redacted: return .blue
        case .allowedUnscanned: return .orange
        }
    }

    var relativeTime: String {
        let seconds = Date().timeIntervalSince(event.date)
        if seconds < 60 { return "just now" }
        let minutes = Int(seconds / 60)
        if minutes < 60 { return "\(minutes)m" }
        let hours = Int(minutes / 60)
        if hours < 24 { return "\(hours)h" }
        return "\(Int(hours / 24))d"
    }

    var body: some View {
        HStack(alignment: .center, spacing: 7) {
            Circle()
                .fill(dotColor)
                .frame(width: 5, height: 5)

            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text(event.providerName)
                        .font(.system(size: 11, weight: .medium))
                        .lineLimit(1)

                    Spacer(minLength: 4)

                    Text(relativeTime)
                        .font(.system(size: 9.5))
                        .foregroundStyle(.tertiary)
                }

                Text(event.matchedCategories.isEmpty ? event.host : event.matchedCategories.joined(separator: ", "))
                    .font(.system(size: 9.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }
}

/// A macOS-native switch with system proportions and feel
private struct NativeSwitch: View {
    @Binding var isOn: Bool

    var body: some View {
        Capsule()
            .fill(isOn ? Color.accentColor : Color.secondary.opacity(0.25))
            .frame(width: 34, height: 20)
            .overlay(
                Circle()
                    .fill(Color.white)
                    .shadow(color: Color.black.opacity(0.2), radius: 1, x: 0, y: 0.5)
                    .padding(2)
                    .frame(width: 20, height: 20)
                    .offset(x: isOn ? 7 : -7)
            )
            .contentShape(Rectangle())
            .onTapGesture {
                withAnimation(.easeInOut(duration: 0.16)) { isOn.toggle() }
            }
    }
}


