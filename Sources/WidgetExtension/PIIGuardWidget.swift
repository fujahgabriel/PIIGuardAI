import SwiftUI
import WidgetKit
import Charts

private struct PIIGuardWidgetEntry: TimelineEntry {
    let date: Date
    let snapshot: WidgetDataSnapshot?
}

private struct PIIGuardWidgetProvider: TimelineProvider {
    func placeholder(in context: Context) -> PIIGuardWidgetEntry {
        PIIGuardWidgetEntry(date: .now, snapshot: nil)
    }

    func getSnapshot(in context: Context, completion: @escaping (PIIGuardWidgetEntry) -> Void) {
        completion(PIIGuardWidgetEntry(date: .now, snapshot: WidgetSnapshotStore.load()))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<PIIGuardWidgetEntry>) -> Void) {
        let entry = PIIGuardWidgetEntry(date: .now, snapshot: WidgetSnapshotStore.load())
        let refreshDate = Date.now.addingTimeInterval(15 * 60)
        completion(Timeline(entries: [entry], policy: .after(refreshDate)))
    }
}

private struct PIIGuardWidgetView: View {
    let entry: PIIGuardWidgetEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        Group {
            if let snapshot = entry.snapshot {
                if family == .systemSmall {
                    smallLayout(snapshot)
                } else {
                    mediumLayout(snapshot)
                }
            } else {
                emptyLayout
            }
        }
        .containerBackground(.background, for: .widget)
    }

    private func smallLayout(_ snapshot: WidgetDataSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                title
                Spacer(minLength: 4)
                statusLabel(snapshot)
            }
            activityChart(snapshot, compact: true)
            HStack {
                metric("Blocked", value: snapshot.blockedCount)
                Spacer(minLength: 8)
                metric("Requests", value: snapshot.requestCount)
            }
            updateLabel(snapshot)
        }
        .padding()
    }

    private func mediumLayout(_ snapshot: WidgetDataSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            title
            HStack(alignment: .top, spacing: 20) {
                VStack(alignment: .leading, spacing: 12) {
                    status(snapshot)
                    HStack(spacing: 22) {
                        metric("Blocked", value: snapshot.blockedCount)
                        metric("Requests", value: snapshot.requestCount)
                    }
                }
                Spacer(minLength: 0)
                activityList(snapshot)
            }
            activityChart(snapshot, compact: false)
            Spacer(minLength: 0)
            updateLabel(snapshot)
        }
        .padding()
    }

    private var title: some View {
        Label("PIIGuard AI", systemImage: "checkmark.shield")
            .font(.headline)
            .lineLimit(1)
    }

    private func status(_ snapshot: WidgetDataSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(snapshot.protectionEnabled ? "Last reported ON" : "Last reported OFF")
                .font(.title3.bold())
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            Text("Mac protection")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func statusLabel(_ snapshot: WidgetDataSnapshot) -> some View {
        Text(snapshot.protectionEnabled ? "ON" : "OFF")
            .font(.caption.bold())
            .foregroundStyle(snapshot.protectionEnabled ? .green : .secondary)
            .lineLimit(1)
    }

    private func activityChart(_ snapshot: WidgetDataSnapshot, compact: Bool) -> some View {
        let activity = snapshot.dailyActivity ?? []
        let maximum = max(1, activity.map(\.requestCount).max() ?? 0)

        return VStack(alignment: .leading, spacing: 2) {
            Text("REQUESTS · 7 DAYS")
                .font(.caption2.bold())
                .foregroundStyle(.secondary)
            Chart(activity) { day in
                BarMark(
                    x: .value("Day", day.day, unit: .day),
                    y: .value("Requests", day.requestCount),
                    width: .ratio(0.55)
                )
                .foregroundStyle(Color.accentColor.gradient)
                .cornerRadius(2)
            }
            .chartYScale(domain: 0...maximum)
            .chartYAxis(.hidden)
            .chartXAxis {
                AxisMarks(values: .stride(by: .day)) { _ in
                    AxisValueLabel(format: .dateTime.weekday(.narrow))
                }
            }
            .frame(height: compact ? 37 : 54)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func metric(_ label: String, value: Int) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text("\(value)")
                .font(.title3.monospacedDigit().bold())
                .contentTransition(.numericText())
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func activityList(_ snapshot: WidgetDataSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("RECENT")
                .font(.caption2.bold())
                .foregroundStyle(.secondary)
            ForEach(snapshot.recentActivity.prefix(2)) { activity in
                HStack(spacing: 6) {
                    Text(activity.providerName)
                        .lineLimit(1)
                    Spacer(minLength: 2)
                    Text(activity.outcome.widgetLabel)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                .font(.caption)
            }
            if snapshot.recentActivity.isEmpty {
                Text("No activity yet")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func updateLabel(_ snapshot: WidgetDataSnapshot) -> some View {
        Text("Updated \(snapshot.updatedAt, style: .relative)")
            .font(.caption2)
            .foregroundStyle(.tertiary)
            .lineLimit(1)
    }

    private var emptyLayout: some View {
        VStack(alignment: .leading, spacing: 8) {
            title
            Spacer(minLength: 0)
            Text("Waiting for Mac data")
                .font(.headline)
            Text("Open PIIGuard AI on your Mac to sync status.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .padding()
    }
}

private extension String {
    var widgetLabel: String {
        switch self {
        case "blocked": "Blocked"
        case "redacted": "Redacted"
        case "allowedUnscanned": "Unscanned"
        default: "Allowed"
        }
    }
}

private struct PIIGuardWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "PIIGuardWidget", provider: PIIGuardWidgetProvider()) { entry in
            PIIGuardWidgetView(entry: entry)
        }
        .configurationDisplayName("PIIGuard AI")
        .description("Mac protection status and recent request activity.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

@main
private struct PIIGuardWidgetBundle: WidgetBundle {
    var body: some Widget {
        PIIGuardWidget()
    }
}