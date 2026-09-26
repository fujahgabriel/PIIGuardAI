import Foundation

enum PrivilegedRunnerError: Error {
    case userCancelled
    case scriptFailed(String)
}

/// Runs shell commands with administrator privileges by asking macOS for a
/// standard authentication prompt via `osascript`. This is the same pattern
/// most small, unsigned-for-personal-use Mac utilities use to make one-off
/// privileged changes (here: trusting our root CA and setting the system
/// proxy) without shipping a separate SMJobBless privileged helper tool.
enum PrivilegedRunner {
    @discardableResult
    static func run(_ shellCommands: [String]) throws -> String {
        let joined = shellCommands
            .map { $0.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }
            .joined(separator: " && ")
        let appleScript = "do shell script \"\(joined)\" with administrator privileges"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", appleScript]

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        try process.run()
        process.waitUntilExit()

        let stdout = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        if process.terminationStatus != 0 {
            if stderr.contains("User canceled") || stderr.contains("-128") {
                throw PrivilegedRunnerError.userCancelled
            }
            throw PrivilegedRunnerError.scriptFailed(stderr.isEmpty ? stdout : stderr)
        }
        return stdout
    }
}
