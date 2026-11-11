import Foundation

enum Severity: String, Codable, CaseIterable, Comparable, Hashable {
    case info, low, medium, high

    var rank: Int {
        switch self {
        case .info: 0
        case .low: 1
        case .medium: 2
        case .high: 3
        }
    }

    static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }
    var label: String { rawValue.capitalized }
}

struct PostureCheck: Codable, Identifiable, Hashable {
    let key: String
    let name: String
    let status: String
    let detail: String
    let fix: String
    let severity: Severity

    var id: String { key }
    var passed: Bool { status == "pass" }
    var failed: Bool { status == "fail" }
}

struct ThreatAlert: Codable, Identifiable, Hashable {
    let id: String
    let severity: Severity
    let title: String
    let detail: String
    let advice: String
    var new: Bool?
    var acked: Bool?
    var firstSeen: String?

    var isAcked: Bool { acked ?? false }
    var isNew: Bool { new ?? false }
    var kind: String { String(id.split(separator: ":").first ?? "") }

    /// The file or program this alert is about, when there is one.
    var subjectPath: String? {
        switch kind {
        case "conn":
            let parts = id.split(separator: ":", maxSplits: 2).map(String.init)
            guard parts.count == 3 else { return nil }
            if parts[1] == "port", let r = parts[2].range(of: ":", options: .backwards) {
                return String(parts[2][..<r.lowerBound])
            }
            return parts[2]
        case "persist", "file":
            return detail.split(separator: "\n").first.map(String.init)
        default:
            return nil
        }
    }

    /// For startup items: the program the launch file runs.
    var programPath: String? {
        guard kind == "persist" else { return subjectPath }
        for line in detail.split(separator: "\n") {
            guard let r = line.range(of: "runs: ") else { continue }
            let rest = line[r.upperBound...]
            let end = rest.range(of: "  (signature")?.lowerBound ?? rest.endIndex
            return String(rest[..<end])
        }
        return subjectPath
    }

    /// The engine's advice is written for the command line; point at the app's buttons instead.
    var appAdvice: String {
        advice
            .replacingOccurrences(of: "run `safeguard.py baseline` to accept it.", with: "use Accept all changes below.")
            .replacingOccurrences(of: "add it to allowlist.json.", with: "use Trust program below.")
            .replacingOccurrences(of: "Add to allowlist.json if expected.", with: "Use Trust program below if expected.")
            .replacingOccurrences(of: "Run `safeguard.py audit` to see how to turn it back on.", with: "The Protection screen shows how to turn it back on.")
    }

    var kindLabel: String {
        switch kind {
        case "persist": "Startup item"
        case "file": "Sensitive file"
        case "cron": "Scheduled job"
        case "listen": "Open port"
        case "app": "New app"
        case "sysext": "System extension"
        case "posture": "Protection"
        case "conn": "Network"
        case "auth": "Login attempts"
        case "trust": "Certificates"
        case "profile": "Profile"
        case "mdm": "Device management"
        case "admin": "Admin account"
        case "user": "User account"
        case "sudo": "sudo"
        case "hook": "Login hook"
        case "btm": "Login item"
        case "dns": "DNS"
        case "mount": "Network drive"
        case "share": "Sharing"
        case "pkg": "Package"
        case "browser": "Browser extension"
        case "tcc": "Permission"
        case "canary": "Ransomware"
        case "shell": "Terminal command"
        case "xprotect": "Malware definitions"
        case "appsig": "App signature"
        default: "Finding"
        }
    }

    var kindIcon: String {
        switch kind {
        case "persist": "power"
        case "file": "doc.badge.gearshape"
        case "cron": "calendar.badge.clock"
        case "listen": "dot.radiowaves.left.and.right"
        case "app": "app.badge"
        case "sysext": "puzzlepiece.extension"
        case "posture": "lock.open"
        case "conn": "network"
        case "auth": "person.badge.key"
        case "trust": "checkmark.seal"
        case "profile": "doc.badge.gearshape"
        case "mdm": "building.2"
        case "admin": "checkmark.shield"
        case "user": "person.badge.plus"
        case "sudo": "terminal"
        case "hook": "arrow.right.to.line"
        case "btm": "power"
        case "dns": "network"
        case "mount": "externaldrive.connected.to.line.below"
        case "share": "folder.badge.person.crop"
        case "pkg": "shippingbox"
        case "browser": "puzzlepiece.extension"
        case "tcc": "eye"
        case "canary": "doc.badge.ellipsis"
        case "shell": "terminal"
        case "xprotect": "shield.lefthalf.filled"
        case "appsig": "app.badge"
        default: "exclamationmark.triangle"
        }
    }
}

struct ThreatEvent: Codable, Hashable {
    let time: String
    let id: String
    let severity: Severity
    let title: String
    let detail: String
}

struct Connection: Codable, Identifiable, Hashable {
    let path: String
    let signature: String
    let remotes: [String]
    var id: String { path }
}

struct Listener: Codable, Identifiable, Hashable {
    let process: String
    let address: String
    let port: Int
    let exposed: Bool
    let known: Bool
    var id: String { "\(process)@\(address)" }
}

struct LaunchItem: Codable, Identifiable, Hashable {
    let path: String
    let program: String
    let signature: String
    let scope: String
    let known: Bool
    let changed: Bool
    var id: String { path }
    var label: String { ((path as NSString).lastPathComponent as NSString).deletingPathExtension }
}

struct HiddenLoginItem: Codable, Identifiable, Hashable {
    let key: String
    let name: String
    let developer: String
    let path: String
    let enabled: Bool
    let known: Bool
    var id: String { key }
    var label: String { name.isEmpty || name == "(null)" ? key : name }
    var developerLabel: String {
        developer.isEmpty || developer == "(null)" || developer == "Unknown Developer"
            ? "Unknown developer" : developer
    }
}

struct CanaryFile: Codable, Identifiable, Hashable {
    let path: String
    let intact: Bool
    var id: String { path }
}

struct DNSInfo: Codable, Hashable {
    let servers: [String]
    let resolvers: [String]
}

struct WatchedFile: Codable, Identifiable, Hashable {
    let path: String
    let severity: Severity
    let why: String
    let state: String
    var id: String { path }
}

struct HistoryPoint: Codable, Hashable {
    let time: String
    let online: Int
    let info: Int
    let low: Int
    let medium: Int
    let high: Int
    var date: Date { Fmt.date(time) ?? .distantPast }
}

struct Allowlist: Codable, Hashable {
    var processes: [String]
    var paths: [String]
}

struct BaselineInfo: Codable, Hashable {
    let taken: String?
    let createdNow: Bool
}

struct ScanStatus: Codable {
    let scannedAt: String
    let computer: String
    let user: String
    let baseline: BaselineInfo
    let posture: [PostureCheck]
    var alerts: [ThreatAlert]
    let connections: [Connection]
    let listening: [Listener]
    let launchItems: [LaunchItem]
    let files: [WatchedFile]
    let appsCount: Int
    let systemExtensions: [String]
    let crontab: [String]
    let history: [HistoryPoint]
    var allowlist: Allowlist
    var scheduleInstalled: Bool
    let dataDir: String
    let report: String
    var backgroundItems: [HiddenLoginItem]?
    var loginItemsChecked: String?
    var canaries: [CanaryFile]?
    var dns: DNSInfo?
    var mounts: [String]?
}

struct URLFinding: Codable, Hashable {
    let severity: Severity
    let message: String
}

struct URLCheck: Codable, Hashable, Identifiable {
    let url: String
    let verdict: String
    let findings: [URLFinding]
    var checkedAt: Date?
    var id: String { url + (checkedAt.map { "\($0.timeIntervalSince1970)" } ?? "") }
}

enum Fmt {
    static let iso: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        return f
    }()

    static func date(_ s: String?) -> Date? { s.flatMap { iso.date(from: $0) } }

    static func relative(_ d: Date?) -> String {
        guard let d else { return "never" }
        if abs(d.timeIntervalSinceNow) < 45 { return "just now" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: d, relativeTo: .now)
    }

    /// "13 hr. ago": for big numbers in narrow tiles.
    static func relativeShort(_ d: Date) -> String {
        if abs(d.timeIntervalSinceNow) < 45 { return "just now" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f.localizedString(for: d, relativeTo: .now)
    }

    static func time(_ d: Date) -> String { d.formatted(date: .omitted, time: .shortened) }
    static func dateTime(_ d: Date) -> String { d.formatted(date: .abbreviated, time: .shortened) }

    static func day(_ d: Date) -> String {
        let cal = Calendar.current
        if cal.isDateInToday(d) { return "Today" }
        if cal.isDateInYesterday(d) { return "Yesterday" }
        return d.formatted(.dateTime.weekday(.wide).month(.abbreviated).day())
    }

    static func tilde(_ path: String) -> String { (path as NSString).abbreviatingWithTildeInPath }

    /// "Google Chrome" for /Applications/Google Chrome.app/Contents/..., else the file name.
    static func programName(_ path: String) -> String {
        if let r = path.range(of: ".app/") {
            return (String(path[..<r.lowerBound]) as NSString).lastPathComponent
        }
        // Tools installed as …/claude/versions/2.1.304: skip version numbers and container folders.
        let skip: Set<String> = ["versions", "bin", "current", "Current", "libexec"]
        for part in path.split(separator: "/").reversed().map(String.init) {
            let isVersion = !part.isEmpty && part.allSatisfy { $0.isNumber || $0 == "." }
            if !isVersion && !skip.contains(part) { return part }
        }
        return (path as NSString).lastPathComponent
    }

    static func bundlePath(_ path: String) -> String? {
        guard let r = path.range(of: ".app/") else { return path.hasSuffix(".app") ? path : nil }
        return String(path[..<r.lowerBound]) + ".app"
    }
}
