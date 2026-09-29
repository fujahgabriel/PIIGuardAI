import Foundation
import WidgetKit

struct WidgetActivity: Codable, Identifiable, Sendable {
    let id: UUID
    let date: Date
    let providerName: String
    let outcome: String
}

struct WidgetDailyActivity: Codable, Identifiable, Sendable {
    let day: Date
    let requestCount: Int

    var id: Date { day }
}

struct WidgetDataSnapshot: Codable, Sendable {
    let protectionEnabled: Bool
    let updatedAt: Date
    let requestCount: Int
    let blockedCount: Int
    let recentActivity: [WidgetActivity]
    let dailyActivity: [WidgetDailyActivity]?
}

enum WidgetSnapshotStore {
    private static let appGroupIdentifier = "group.com.piiguard.app"
    private static let snapshotFilename = "widget-data-snapshot.json"

    static func publish(_ snapshot: WidgetDataSnapshot) {
        guard let data = try? JSONEncoder().encode(snapshot),
              let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier) else { return }
        let snapshotURL = containerURL.appendingPathComponent(snapshotFilename)
        guard (try? data.write(to: snapshotURL, options: .atomic)) != nil else { return }
        WidgetCenter.shared.reloadTimelines(ofKind: "PIIGuardWidget")
    }

    static func load() -> WidgetDataSnapshot? {
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier),
              let data = try? Data(contentsOf: containerURL.appendingPathComponent(snapshotFilename)) else { return nil }
        return try? JSONDecoder().decode(WidgetDataSnapshot.self, from: data)
    }
}