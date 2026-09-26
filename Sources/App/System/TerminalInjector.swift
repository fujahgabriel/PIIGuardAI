import Foundation

enum TerminalInjectorError: Error {
    case scriptCreationFailed
    case executionFailed(String)
}

extension TerminalInjectorError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .scriptCreationFailed: return "Could not prepare the Terminal automation script."
        case .executionFailed(let message): return "Terminal automation failed: \(message)"
        }
    }
}

/// Injects the CLI proxy `source` command into every open, idle Terminal.app
/// tab, so existing terminal sessions pick up (or drop) proxy/CA env vars
/// without the user closing anything.
///
/// Opt-in only (see `AppState.autoInjectIntoTerminal`): this literally types
/// a command into the user's terminal windows on their behalf, which is
/// exactly the kind of behavior that looks alarming if it happens without
/// having been explicitly asked for. Busy tabs (an active foreground
/// program -- vim, ssh, a long build, an interactive REPL) are always
/// skipped so we never interrupt something in progress.
///
/// Only Terminal.app is supported: it ships a proper AppleScript scripting
/// dictionary for this (`do script ... in tab`). Electron-based terminals
/// (Hyper, and most others) don't expose scriptable windows/tabs at all.
enum TerminalInjector {
    @discardableResult
    static func injectIntoOpenTabs(shellCommand: String) -> Result<Int, Error> {
        let escaped = shellCommand
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        // Checking "is running" outside the `tell` block matters: sending
        // *any* command inside `tell application "Terminal"` launches it as
        // a side effect if it wasn't already open, which we don't want.
        let source = """
        if application "Terminal" is running then
            tell application "Terminal"
                set updatedCount to 0
                repeat with w in windows
                    repeat with t in tabs of w
                        if not busy of t then
                            do script "\(escaped)" in t
                            set updatedCount to updatedCount + 1
                        end if
                    end repeat
                end repeat
                return updatedCount
            end tell
        else
            return 0
        end if
        """

        guard let script = NSAppleScript(source: source) else {
            return .failure(TerminalInjectorError.scriptCreationFailed)
        }
        var errorDict: NSDictionary?
        let result = script.executeAndReturnError(&errorDict)
        if let errorDict {
            let message = (errorDict[NSAppleScript.errorMessage] as? String) ?? "unknown AppleScript error"
            return .failure(TerminalInjectorError.executionFailed(message))
        }
        return .success(Int(result.int32Value))
    }
}
