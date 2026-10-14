import SwiftUI

struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(spacing: 12) {
            // Header / Hero Status Card
            headerCard

            // Error Callout (if any)
            if let error = appState.lastError {
                errorBanner(error)
            }

            // Mode Selector (Auto-Redact vs Block)
            modeSelector

            // Metrics Ribbon
            metricsRibbon

            Divider()
                .opacity(0.6)

            // Activity Section
            activitySection

            Divider()
                .opacity(0.6)

            // Footer Actions
            footerBar
        }
        .padding(14)
        .frame(width: 340)
    }

    // MARK: - Header & Hero Card

    private var headerCard: some View {
        HStack(alignment: .center, spacing: 12) {
            ZStack {
                Circle()
                    .fill(appState.isProtecting ? Color.green.opacity(0.15) : Color.secondary.opacity(0.12))
                    .frame(width: 40, height: 40)

                Image(systemName: appState.isProtecting ? "shield.checkmark.fill" : "shield.slash.fill")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(appState.isProtecting ? Color.green : Color.secondary)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(AppIdentity.displayName)
                    .font(.headline)
                    .fontWeight(.semibold)

                HStack(spacing: 5) {
                    if appState.isBusy {
                        ProgressView()
                            .controlSize(.mini)
                        Text("Configuring…")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else if appState.isProtecting {
                        Circle()
                            .fill(Color.green)
                            .frame(width: 6, height: 6)
                        Text("Protection Active")
                            .font(.caption)
                            .fontWeight(.medium)
                            .foregroundStyle(.green)
                    } else {
                        Circle()
                            .fill(Color.secondary.opacity(0.6))
                            .frame(width: 6, height: 6)
                        Text("Protection Paused")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Spacer(minLength: 4)

            PillToggle(isOn: Binding(
                get: { appState.isProtecting },
                set: { newValue in newValue ? appState.startProtection() : appState.stopProtection() }
            ))
            .opacity(appState.isBusy ? 0.6 : 1.0)
            .allowsHitTesting(!appState.isBusy)
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(0.6))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(Color.secondary.opacity(0.15), lineWidth: 1)
        )
    }

    // MARK: - Error Banner

    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .font(.caption)
                .padding(.top, 1)

            Text(message)
                .font(.caption)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)

            Spacer(minLength: 0)
        }
        .padding(8)
        .background(Color.red.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    // MARK: - Mode Selector

    private var modeSelector: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                modeButton(
                    title: "Auto-Redact",
                    icon: "eye.slash.fill",
                    isSelected: appState.autoRedactEnabled,
                    activeColor: .blue
                ) {
                    withAnimation(.easeInOut(duration: 0.18)) {
                        appState.autoRedactEnabled = true
                    }
                }

                modeButton(
                    title: "Block Mode",
                    icon: "hand.raised.fill",
                    isSelected: !appState.autoRedactEnabled,
                    activeColor: .red
                ) {
                    withAnimation(.easeInOut(duration: 0.18)) {
                        appState.autoRedactEnabled = false
                    }
                }
            }

            Text(appState.autoRedactEnabled
                 ? "Masks sensitive PII with [REDACTED] tokens so prompts still complete."
                 : "Blocks messages containing PII with an HTTP 403 Forbidden response.")
                .font(.system(size: 10.5))
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 2)
        }
    }

    private func modeButton(title: String, icon: String, isSelected: Bool, activeColor: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.caption2)
                Text(title)
                    .font(.caption)
                    .fontWeight(isSelected ? .semibold : .regular)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(isSelected ? activeColor.opacity(0.15) : Color(nsColor: .controlBackgroundColor).opacity(0.4))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(isSelected ? activeColor.opacity(0.6) : Color.secondary.opacity(0.15), lineWidth: 1)
            )
            .foregroundStyle(isSelected ? activeColor : .primary)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Metrics Ribbon

    private var metricsRibbon: some View {
        HStack(spacing: 8) {
            metricCard(title: "Redacted", value: appState.redactedCount, icon: "eye.slash", color: .blue)
            metricCard(title: "Blocked", value: appState.blockedCount, icon: "hand.raised", color: .red)
            metricCard(title: "Allowed", value: appState.allowedCount, icon: "checkmark", color: .green)
        }
    }

    private func metricCard(title: String, value: Int, icon: String, color: Color) -> some View {
        VStack(spacing: 3) {
            HStack(spacing: 3) {
                Image(systemName: icon)
                    .font(.system(size: 9, weight: .bold))
                Text(title)
                    .font(.system(size: 10, weight: .medium))
            }
            .foregroundStyle(color)

            Text("\(value)")
                .font(.system(size: 17, weight: .bold, design: .rounded))
                .foregroundStyle(.primary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(color.opacity(0.06))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(color.opacity(0.15), lineWidth: 1)
        )
    }

    // MARK: - Activity Feed

    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Recent Activity")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)

                Spacer()

                if !appState.events.isEmpty {
                    Button("View All") {
                        openSettings()
                        NSApp.activate(ignoringOtherApps: true)
                    }
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(Color.accentColor)
                    .buttonStyle(.plain)
                }
            }

            if appState.events.isEmpty {
                VStack(spacing: 4) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 18))
                        .foregroundStyle(.secondary.opacity(0.5))
                        .padding(.top, 6)
                    Text("No AI traffic observed yet")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("Prompts to configured providers will be scanned here.")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary.opacity(0.7))
                        .padding(.bottom, 6)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(appState.events.prefix(6)) { event in
                            EventCard(event: event)
                        }
                    }
                    .padding(.vertical, 2)
                }
                .frame(maxHeight: 145)
            }
        }
    }

    // MARK: - Footer Bar

    private var footerBar: some View {
        HStack(spacing: 8) {
            Button {
                openSettings()
                NSApp.activate(ignoringOtherApps: true)
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "gearshape")
                        .font(.caption)
                    Text("Settings…")
                        .font(.caption)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
                .background(Color(nsColor: .controlBackgroundColor).opacity(0.4))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            }
            .buttonStyle(.plain)
            .keyboardShortcut(",", modifiers: .command)

            Button {
                NSApp.terminate(nil)
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "power")
                        .font(.caption)
                    Text("Quit")
                        .font(.caption)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
                .background(Color(nsColor: .controlBackgroundColor).opacity(0.4))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            }
            .buttonStyle(.plain)
            .keyboardShortcut("q", modifiers: .command)
        }
    }
}

// MARK: - Custom Views

private struct EventCard: View {
    let event: TrafficEvent

    var icon: String {
        switch event.outcome {
        case .blocked: return "hand.raised.fill"
        case .allowed: return "checkmark.circle.fill"
        case .redacted: return "eye.slash.fill"
        case .allowedUnscanned: return "questionmark.circle.fill"
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

    var outcomeBadgeText: String {
        switch event.outcome {
        case .blocked: return "Blocked"
        case .allowed: return "Allowed"
        case .redacted: return "Redacted"
        case .allowedUnscanned: return "Unscanned"
        }
    }

    var relativeTime: String {
        let seconds = Date().timeIntervalSince(event.date)
        if seconds < 60 { return "just now" }
        let minutes = Int(seconds / 60)
        if minutes < 60 { return "\(minutes)m ago" }
        let hours = Int(minutes / 60)
        if hours < 24 { return "\(hours)h ago" }
        return "\(Int(hours / 24))d ago"
    }

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .font(.caption)
                .frame(width: 14)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(event.providerName)
                        .font(.system(size: 11, weight: .semibold))
                        .lineLimit(1)

                    Spacer(minLength: 0)

                    Text(relativeTime)
                        .font(.system(size: 9.5))
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 4) {
                    Text(outcomeBadgeText)
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(color)
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(color.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 3, style: .continuous))

                    if !event.matchedCategories.isEmpty {
                        Text(event.matchedCategories.joined(separator: ", "))
                            .font(.system(size: 9.5))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    } else {
                        Text(event.host)
                            .font(.system(size: 9.5))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(0.3))
        )
    }
}

private struct PillToggle: View {
    @Binding var isOn: Bool

    var body: some View {
        Capsule()
            .fill(isOn ? Color.green : Color.secondary.opacity(0.3))
            .frame(width: 38, height: 22)
            .overlay(
                Circle()
                    .fill(Color.white)
                    .shadow(color: Color.black.opacity(0.15), radius: 1, x: 0, y: 1)
                    .padding(2)
                    .frame(width: 22, height: 22)
                    .offset(x: isOn ? 8 : -8)
            )
            .contentShape(Rectangle())
            .onTapGesture {
                withAnimation(.easeInOut(duration: 0.15)) { isOn.toggle() }
            }
    }
}

