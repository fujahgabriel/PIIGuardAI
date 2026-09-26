import SwiftUI
import Charts

struct ActivityTabView: View {
    @EnvironmentObject var appState: AppState
    @State private var filter: OutcomeFilter = .all
    @State private var providerFilter: String = Self.allProvidersOption
    @State private var categoryFilter: String = Self.allCategoriesOption
    @State private var searchText: String = ""
    @State private var showingClearConfirmation = false
    @State private var chartRangeDays = 14

    private static let allProvidersOption = "All providers"
    private static let allCategoriesOption = "All categories"
    private static let chartRangeOptions = [7, 14, 30, 90]

    private enum OutcomeFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case blocked = "Blocked"
        case allowed = "Allowed"
        case redacted = "Redacted"
        case unscanned = "Unscanned"
        var id: String { rawValue }
    }

    private var availableProviders: [String] {
        [Self.allProvidersOption] + Set(appState.events.map(\.providerName)).sorted()
    }

    private var availableCategories: [String] {
        [Self.allCategoriesOption] + Set(appState.events.flatMap(\.matchedCategories)).sorted()
    }

    private var filteredEvents: [TrafficEvent] {
        appState.events.filter { event in
            switch filter {
            case .all: break
            case .blocked: guard event.outcome == .blocked else { return false }
            case .allowed: guard event.outcome == .allowed else { return false }
            case .redacted: guard event.outcome == .redacted else { return false }
            case .unscanned: guard event.outcome == .allowedUnscanned else { return false }
            }
            if providerFilter != Self.allProvidersOption, event.providerName != providerFilter {
                return false
            }
            if categoryFilter != Self.allCategoriesOption, !event.matchedCategories.contains(categoryFilter) {
                return false
            }
            let trimmedSearch = searchText.trimmingCharacters(in: .whitespaces)
            if !trimmedSearch.isEmpty {
                let haystack = "\(event.providerName) \(event.host) \(event.matchedCategories.joined(separator: " "))"
                guard haystack.localizedCaseInsensitiveContains(trimmedSearch) else { return false }
            }
            return true
        }
    }

    private var filtersActive: Bool {
        !searchText.isEmpty || providerFilter != Self.allProvidersOption || categoryFilter != Self.allCategoriesOption
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            summaryRow

            TrendChartCard(daily: appState.dailyCounts(days: chartRangeDays), days: chartRangeDays, rangeSelection: $chartRangeDays, rangeOptions: Self.chartRangeOptions)

            HStack(alignment: .top, spacing: 16) {
                if !appState.categoryCounts.isEmpty {
                    BreakdownChartCard(title: "Blocked by category", rows: appState.categoryCounts)
                }
                if !appState.providerCounts.isEmpty {
                    BreakdownChartCard(title: "Traffic by provider", rows: appState.providerCounts)
                }
            }

            Text("Log").font(.headline)

            Picker("", selection: $filter) {
                ForEach(OutcomeFilter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .fixedSize()

            HStack {
                Picker("Provider", selection: $providerFilter) {
                    ForEach(availableProviders, id: \.self) { Text($0).tag($0) }
                }
                .frame(width: 170)
                Picker("Category", selection: $categoryFilter) {
                    ForEach(availableCategories, id: \.self) { Text($0).tag($0) }
                }
                .frame(width: 170)
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search provider, host, or category", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                if filtersActive {
                    Button("Reset") {
                        searchText = ""
                        providerFilter = Self.allProvidersOption
                        categoryFilter = Self.allCategoriesOption
                    }
                    .font(.caption)
                }
            }

            if filteredEvents.isEmpty {
                Text(appState.events.isEmpty ? "No traffic observed yet." : "No log entries match this filter.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.top, 20)
                Spacer()
            } else {
                List(filteredEvents) { event in
                    LogRow(event: event)
                }
                .listStyle(.inset)
            }

            HStack(spacing: 8) {
                Button("Reveal log file in Finder") {
                    appState.revealActivityLogInFinder()
                }
                Button("Copy log") {
                    _ = appState.copyActivityLogToPasteboard()
                }
                .help("Copy entire activity-log.jsonl to clipboard")
                Spacer()
                Button("Clear log", role: .destructive) {
                    showingClearConfirmation = true
                }
                .confirmationDialog(
                    "This permanently deletes \(AppIdentity.displayName)'s local activity history.",
                    isPresented: $showingClearConfirmation,
                    titleVisibility: .visible
                ) {
                    Button("Clear", role: .destructive) { appState.clearActivityLog() }
                    Button("Cancel", role: .cancel) {}
                }
            }
        }
        .padding()
    }

    private var summaryRow: some View {
        HStack(spacing: 10) {
            StatTile(title: "Total", value: appState.events.count, tint: .primary)
            StatTile(title: "Blocked", value: appState.blockedCount, tint: .red)
            StatTile(title: "Allowed", value: appState.allowedCount, tint: .green)
            StatTile(title: "Redacted", value: appState.redactedCount, tint: .blue)
            StatTile(title: "Unscanned", value: appState.unscannedCount, tint: .orange)
        }
    }
}

private struct StatTile: View {
    let title: String
    let value: Int
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(value)")
                .font(.title2)
                .fontWeight(.semibold)
                .foregroundStyle(tint)
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

/// Stacked bar chart of every request over the last 14 days, broken out by
/// outcome (blocked / allowed / allowed-but-unscanned).
private struct TrendChartCard: View {
    let daily: [(day: Date, blocked: Int, allowed: Int, unscanned: Int, redacted: Int)]
    let days: Int
    @Binding var rangeSelection: Int
    let rangeOptions: [Int]

    private var hasAnyData: Bool { daily.contains { $0.blocked > 0 || $0.allowed > 0 || $0.unscanned > 0 || $0.redacted > 0 } }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Last \(days) days").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Picker("", selection: $rangeSelection) {
                    ForEach(rangeOptions, id: \.self) { option in
                        Text("\(option)d").tag(option)
                    }
                }
                .pickerStyle(.segmented)
                .fixedSize()
            }
            if hasAnyData {
                Chart(daily, id: \.day) { point in
                    BarMark(
                        x: .value("Day", point.day, unit: .day),
                        y: .value("Messages", point.blocked)
                    )
                    .foregroundStyle(by: .value("Outcome", "Blocked"))
                    BarMark(
                        x: .value("Day", point.day, unit: .day),
                        y: .value("Messages", point.allowed)
                    )
                    .foregroundStyle(by: .value("Outcome", "Allowed"))
                    BarMark(
                        x: .value("Day", point.day, unit: .day),
                        y: .value("Messages", point.redacted)
                    )
                    .foregroundStyle(by: .value("Outcome", "Redacted"))
                    BarMark(
                        x: .value("Day", point.day, unit: .day),
                        y: .value("Messages", point.unscanned)
                    )
                    .foregroundStyle(by: .value("Outcome", "Unscanned"))
                }
                .chartForegroundStyleScale([
                    "Blocked": Color.red,
                    "Allowed": Color.green,
                    "Redacted": Color.blue,
                    "Unscanned": Color.orange,
                ])
                .chartLegend(position: .top, alignment: .leading, spacing: 4)
                .frame(height: 110)
            } else {
                Text("Not enough traffic yet to chart.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(height: 110, alignment: .center)
                    .frame(maxWidth: .infinity)
            }
        }
    }
}

/// Horizontal bar chart used for both the category and provider breakdowns.
private struct BreakdownChartCard: View {
    let title: String
    let rows: [(name: String, count: Int)]

    private var topRows: [(name: String, count: Int)] { Array(rows.prefix(6)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Chart(topRows, id: \.name) { row in
                BarMark(
                    x: .value("Count", row.count),
                    y: .value("Name", row.name)
                )
                .foregroundStyle(Color.accentColor.gradient)
                .annotation(position: .trailing) {
                    Text("\(row.count)").font(.caption2).foregroundStyle(.secondary)
                }
            }
            .chartXAxis(.hidden)
            .frame(height: CGFloat(topRows.count) * 22 + 10)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct LogRow: View {
    let event: TrafficEvent

    private var icon: String {
        switch event.outcome {
        case .blocked: return "hand.raised.fill"
        case .allowed: return "checkmark.circle"
        case .redacted: return "eye.slash.circle"
        case .allowedUnscanned: return "questionmark.circle"
        }
    }

    private var color: Color {
        switch event.outcome {
        case .blocked: return .red
        case .allowed: return .green
        case .redacted: return .blue
        case .allowedUnscanned: return .orange
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 1) {
                Text(event.summary).font(.callout)
                Text(event.date, style: .date) + Text(" · ") + Text(event.date, style: .time)
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.vertical, 2)
    }
}
