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

            if !appState.categoryCounts.isEmpty || !appState.providerCounts.isEmpty {
                HStack(alignment: .top, spacing: 12) {
                    if !appState.categoryCounts.isEmpty {
                        BreakdownChartCard(title: "Top Blocked Categories", rows: appState.categoryCounts)
                    }
                    if !appState.providerCounts.isEmpty {
                        BreakdownChartCard(title: "Traffic by Provider", rows: appState.providerCounts)
                    }
                }
            }

            // MARK: - Filter Bar
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Picker("", selection: $filter) {
                        Text("All (\(appState.events.count))").tag(OutcomeFilter.all)
                        Text("Blocked (\(appState.blockedCount))").tag(OutcomeFilter.blocked)
                        Text("Redacted (\(appState.redactedCount))").tag(OutcomeFilter.redacted)
                        Text("Allowed (\(appState.allowedCount))").tag(OutcomeFilter.allowed)
                        if appState.unscannedCount > 0 {
                            Text("Unscanned (\(appState.unscannedCount))").tag(OutcomeFilter.unscanned)
                        }
                    }
                    .pickerStyle(.segmented)

                    Spacer()

                    if filtersActive {
                        Button("Reset Filters") {
                            searchText = ""
                            providerFilter = Self.allProvidersOption
                            categoryFilter = Self.allCategoriesOption
                        }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        .foregroundStyle(.tint)
                    }
                }

                HStack(spacing: 8) {
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                        TextField("Search host, provider, category...", text: $searchText)
                            .textFieldStyle(.plain)
                            .font(.callout)
                        if !searchText.isEmpty {
                            Button {
                                searchText = ""
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(.secondary)
                                    .font(.caption)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Color(nsColor: .controlBackgroundColor))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 6))

                    Menu {
                        ForEach(availableProviders, id: \.self) { prov in
                            Button(prov) { providerFilter = prov }
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "network")
                            Text(providerFilter)
                                .lineLimit(1)
                        }
                    }
                    .menuStyle(.borderlessButton)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Color(nsColor: .controlBackgroundColor))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .font(.caption)

                    Menu {
                        ForEach(availableCategories, id: \.self) { cat in
                            Button(cat) { categoryFilter = cat }
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "tag")
                            Text(categoryFilter)
                                .lineLimit(1)
                        }
                    }
                    .menuStyle(.borderlessButton)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Color(nsColor: .controlBackgroundColor))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .font(.caption)
                }
            }

            // MARK: - Log Table / List
            if filteredEvents.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 28))
                        .foregroundStyle(.secondary.opacity(0.6))
                    Text(appState.events.isEmpty ? "No AI traffic observed yet." : "No log events match your filter criteria.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filteredEvents) { event in
                    LogRow(event: event)
                        .listRowInsets(EdgeInsets(top: 4, leading: 6, bottom: 4, trailing: 6))
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.secondary.opacity(0.15), lineWidth: 1)
                )
            }

            // MARK: - Footer Actions
            HStack(spacing: 10) {
                Button {
                    appState.revealActivityLogInFinder()
                } label: {
                    Label("Reveal Log in Finder", systemImage: "folder")
                }

                Button {
                    _ = appState.copyActivityLogToPasteboard()
                } label: {
                    Label("Copy Log", systemImage: "doc.on.doc")
                }
                .help("Copy activity log to clipboard")

                Spacer()

                Button(role: .destructive) {
                    showingClearConfirmation = true
                } label: {
                    Label("Clear Log…", systemImage: "trash")
                }
                .confirmationDialog(
                    "This permanently deletes \(AppIdentity.displayName)'s local activity history.",
                    isPresented: $showingClearConfirmation,
                    titleVisibility: .visible
                ) {
                    Button("Clear History", role: .destructive) { appState.clearActivityLog() }
                    Button("Cancel", role: .cancel) {}
                }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(14)
    }

    private var summaryRow: some View {
        HStack(spacing: 0) {
            MetricItem(title: "Total Requests", value: appState.events.count, icon: "tray.full.fill", tint: .primary)
            Divider().frame(height: 28)
            MetricItem(title: "Blocked", value: appState.blockedCount, icon: "hand.raised.fill", tint: .red)
            Divider().frame(height: 28)
            MetricItem(title: "Redacted", value: appState.redactedCount, icon: "eye.slash.fill", tint: .blue)
            Divider().frame(height: 28)
            MetricItem(title: "Allowed", value: appState.allowedCount, icon: "checkmark.circle.fill", tint: .green)
            if appState.unscannedCount > 0 {
                Divider().frame(height: 28)
                MetricItem(title: "Unscanned", value: appState.unscannedCount, icon: "questionmark.circle.fill", tint: .orange)
            }
        }
        .padding(.vertical, 8)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.7))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.secondary.opacity(0.15), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct MetricItem: View {
    let title: String
    let value: Int
    let icon: String
    let tint: Color

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 15))
                .foregroundStyle(tint)

            VStack(alignment: .leading, spacing: 0) {
                Text("\(value)")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(tint == .primary ? Color.primary : tint)
                Text(title)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 6)
    }
}

/// Stacked bar chart of every request over selected days, broken out by outcome
private struct TrendChartCard: View {
    let daily: [(day: Date, blocked: Int, allowed: Int, unscanned: Int, redacted: Int)]
    let days: Int
    @Binding var rangeSelection: Int
    let rangeOptions: [Int]

    private var hasAnyData: Bool { daily.contains { $0.blocked > 0 || $0.allowed > 0 || $0.unscanned > 0 || $0.redacted > 0 } }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Label("Activity (Past \(days) Days)", systemImage: "chart.bar.xaxis")
                    .font(.caption)
                    .fontWeight(.medium)
                    .foregroundStyle(.secondary)
                Spacer()
                Picker("", selection: $rangeSelection) {
                    ForEach(rangeOptions, id: \.self) { option in
                        Text("\(option)d").tag(option)
                    }
                }
                .pickerStyle(.segmented)
                .controlSize(.mini)
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
                        y: .value("Messages", point.redacted)
                    )
                    .foregroundStyle(by: .value("Outcome", "Redacted"))
                    BarMark(
                        x: .value("Day", point.day, unit: .day),
                        y: .value("Messages", point.allowed)
                    )
                    .foregroundStyle(by: .value("Outcome", "Allowed"))
                    if point.unscanned > 0 {
                        BarMark(
                            x: .value("Day", point.day, unit: .day),
                            y: .value("Messages", point.unscanned)
                        )
                        .foregroundStyle(by: .value("Outcome", "Unscanned"))
                    }
                }
                .chartForegroundStyleScale([
                    "Blocked": Color.red,
                    "Redacted": Color.blue,
                    "Allowed": Color.green,
                    "Unscanned": Color.orange,
                ])
                .chartLegend(position: .top, alignment: .leading, spacing: 10)
                .frame(height: 95)
            } else {
                Text("No traffic recorded during this time period.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(height: 95, alignment: .center)
                    .frame(maxWidth: .infinity)
            }
        }
        .padding(10)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.4))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.secondary.opacity(0.15), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

/// Horizontal bar chart used for category and provider breakdowns
private struct BreakdownChartCard: View {
    let title: String
    let rows: [(name: String, count: Int)]

    private var topRows: [(name: String, count: Int)] { Array(rows.prefix(4)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption2)
                .fontWeight(.medium)
                .foregroundStyle(.secondary)

            Chart(topRows, id: \.name) { row in
                BarMark(
                    x: .value("Count", row.count),
                    y: .value("Name", row.name)
                )
                .foregroundStyle(Color.accentColor.gradient)
                .annotation(position: .trailing) {
                    Text("\(row.count)")
                        .font(.system(size: 9, weight: .medium))
                        .foregroundStyle(.secondary)
                }
            }
            .chartXAxis(.hidden)
            .chartYAxis {
                AxisMarks(values: .automatic) { value in
                    AxisValueLabel()
                        .font(.system(size: 10))
                }
            }
            .frame(height: CGFloat(max(topRows.count, 1)) * 20 + 8)
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.4))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(Color.secondary.opacity(0.15), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

private struct LogRow: View {
    let event: TrafficEvent

    private var icon: String {
        switch event.outcome {
        case .blocked: return "hand.raised.fill"
        case .allowed: return "checkmark.circle.fill"
        case .redacted: return "eye.slash.fill"
        case .allowedUnscanned: return "questionmark.circle.fill"
        }
    }

    private var tint: Color {
        switch event.outcome {
        case .blocked: return .red
        case .allowed: return .green
        case .redacted: return .blue
        case .allowedUnscanned: return .orange
        }
    }

    private var outcomeLabel: String {
        switch event.outcome {
        case .blocked: return "BLOCKED"
        case .allowed: return "ALLOWED"
        case .redacted: return "REDACTED"
        case .allowedUnscanned: return "PASSED"
        }
    }

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 14))
                .foregroundStyle(tint)
                .frame(width: 16)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(outcomeLabel)
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(tint)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(tint.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 4))

                    Text(event.providerName)
                        .font(.system(size: 12, weight: .semibold))

                    Text(event.host)
                        .font(.caption2)
                        .foregroundStyle(.secondary)

                    Spacer()

                    Text(event.date, style: .time)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                }

                if !event.matchedCategories.isEmpty {
                    HStack(spacing: 4) {
                        Text("Detected:")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)

                        ForEach(event.matchedCategories, id: \.self) { cat in
                            Text(cat)
                                .font(.system(size: 9.5))
                                .padding(.horizontal, 4)
                                .padding(.vertical, 1)
                                .background(Color.secondary.opacity(0.12))
                                .clipShape(RoundedRectangle(cornerRadius: 3))
                        }
                    }
                }
            }
        }
        .padding(.vertical, 3)
    }
}
