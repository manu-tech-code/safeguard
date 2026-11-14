import AppKit
import ServiceManagement
import SwiftUI
import UserNotifications

enum Screen: String, CaseIterable, Identifiable {
    case overview, threats, protection, network, browser, startup, links, advisor, activity, settings
    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: "Overview"
        case .threats: "Threats"
        case .protection: "Protection"
        case .network: "Network"
        case .browser: "Browser"
        case .startup: "Startup Items"
        case .links: "Link Shield"
        case .advisor: "Advisor"
        case .activity: "Activity"
        case .settings: "Settings"
        }
    }

    var subtitle: String {
        switch self {
        case .overview: "Your Mac's security at a glance"
        case .threats: "Everything that changed or looks wrong since your baseline"
        case .protection: "The protections built into macOS, and whether they're on"
        case .network: "Which programs are talking to the internet, and who can reach you"
        case .browser: "Sites you visited, read from local browser history"
        case .startup: "What launches automatically, and the files attackers tamper with"
        case .links: "Check a link before you click it"
        case .advisor: "The AI that explains a finding and proposes a fix you approve"
        case .activity: "Every scan and finding over time"
        case .settings: "How and when Safeguard watches"
        }
    }

    var icon: String {
        switch self {
        case .overview: "square.grid.2x2"
        case .threats: "exclamationmark.shield"
        case .protection: "lock.shield"
        case .network: "network"
        case .browser: "safari"
        case .startup: "power"
        case .links: "link"
        case .advisor: "sparkles"
        case .activity: "waveform.path.ecg"
        case .settings: "gearshape"
        }
    }
}

enum ThreatLevel {
    case secure, watch, danger

    var color: Color {
        switch self {
        case .secure: Theme.green
        case .watch: Theme.accent
        case .danger: Theme.red
        }
    }

    var title: String {
        switch self {
        case .secure: "Protected"
        case .watch: "Needs attention"
        case .danger: "Under threat"
        }
    }
}

struct LogLine: Identifiable {
    let time: String
    let level: Severity?
    let message: String
    var id: String { time + message }
}

struct ConfirmRequest: Identifiable {
    let id = UUID()
    let title: String
    let message: String
    let action: String
    var destructive = false
    let perform: () async -> Void
}

@MainActor
@Observable
final class AppStore {
    static let shared = AppStore()

    static let snapshotDir: URL? = {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--snapshot"), i + 1 < args.count else { return nil }
        return URL(fileURLWithPath: args[i + 1])
    }()

    var status: ScanStatus?
    var events: [ThreatEvent] = []
    var scanning = false
    var errorMessage: String?
    var screen: Screen = .overview
    var selectedAlertID: String?
    var urlChecks: [URLCheck] = []
    var checkingURL = false
    var confirm: ConfirmRequest?
    var toast: String?

    // Advisor (optional AI mediator)
    var advisor: AdvisorStatus?
    var advisorProposal: AdvisorProposal?
    var advisorAlertID: String?
    var advisorBusy = false
    var fixing = false
    var lastFix: FixOutcome?
    var lastFixAlertID: String?
    var advisorCheckKey: String?
    var advisorRequestKey: String?
    var advisorDigest: AdvisorDigest?
    var digestBusy = false
    var followups: [AdvisorExchange] = []
    var followupBusy = false
    var fixRecords: [FixRecord] = []
    var loginItemsBusy = false
    var browser: BrowserOverview?
    var browserLoading = false
    var browserDays = 7
    var browserQuery = ""
    var browserUpdatedAt: Date?
    var bridgeProcess: Process?
    var browserSweep: BrowserSweep?
    var sweepBusy = false
    var agentModels: [AgentModel] = []
    var modelsLoading = false
    var modelError: String?

    var autoScan: Bool
    var intervalMinutes: Int
    var notificationsOn: Bool
    /// Which look the app draws in. Change it with `setLook(_:)` so `Theme` follows.
    private(set) var look: Look
    /// Closing the window leaves Safeguard running in the menu bar, still scanning.
    var runInBackground: Bool
    var showInMenuBar: Bool
    var launchAtLogin = SMAppService.mainApp.status == .enabled
    /// nil until macOS answers; false means the user blocked Safeguard in Settings.
    var notificationsAllowed: Bool?
    /// Set by a view that can open the main window (SwiftUI only hands `openWindow` to views).
    var openMainWindowAction: (() -> Void)?

    /// `--look bento|fieldops` on the command line overrides the saved choice (used for snapshots).
    static let forcedLook: Look? = {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--look"), i + 1 < args.count else { return nil }
        return Look(rawValue: args[i + 1])
    }()

    /// True when macOS started Safeguard as a login item, so it should stay in the menu bar.
    static let launchedAtLogin: Bool = {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventID == kAEOpenApplication
            && event.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem
    }()

    private var loopTask: Task<Void, Never>?
    private var napGuard: NSObjectProtocol?
    private var toastTask: Task<Void, Never>?

    init() {
        let d = UserDefaults.standard
        autoScan = d.object(forKey: "autoScan") as? Bool ?? true
        intervalMinutes = d.object(forKey: "intervalMinutes") as? Int ?? 5
        notificationsOn = d.object(forKey: "notifications") as? Bool ?? true
        runInBackground = d.object(forKey: "runInBackground") as? Bool ?? true
        showInMenuBar = d.object(forKey: "showInMenuBar") as? Bool ?? true
        look = AppStore.forcedLook ?? Look(rawValue: d.string(forKey: "look") ?? "") ?? .bento
        Theme.look = look
        if let data = d.data(forKey: "urlChecks"),
           let saved = try? JSONDecoder().decode([URLCheck].self, from: data) {
            urlChecks = saved
        }
    }

    // MARK: derived state

    var lastScanDate: Date? { Fmt.date(status?.scannedAt) }

    var activeAlerts: [ThreatAlert] {
        (status?.alerts ?? []).filter { !$0.isAcked }.sorted { $0.severity > $1.severity }
    }

    var checks: [PostureCheck] { (status?.posture ?? []).filter { $0.severity != .info } }
    var failingChecks: [PostureCheck] { checks.filter(\.failed) }

    var score: Int {
        var v = 100.0
        for c in failingChecks {
            v -= [Severity.high: 18, .medium: 8, .low: 3, .info: 0][c.severity] ?? 0
        }
        for a in activeAlerts {
            v -= [Severity.high: 15, .medium: 6, .low: 2, .info: 0][a.severity] ?? 0
        }
        return max(0, min(100, Int(v)))
    }

    var level: ThreatLevel {
        if activeAlerts.contains(where: { $0.severity == .high }) { return .danger }
        if activeAlerts.contains(where: { $0.severity == .medium }) { return .watch }
        if failingChecks.contains(where: { $0.severity >= .medium }) { return .watch }
        return .secure
    }

    func count(_ s: Severity) -> Int { activeAlerts.filter { $0.severity == s }.count }

    /// One-line summary used by the Overview hero and the menu bar panel.
    var headline: String {
        let fileChanged = activeAlerts.contains { $0.kind == "file" }
        let off = failingChecks.count
        let offPhrase = "\(Self.countWord(off)) protection\(off == 1 ? " is" : "s are")"
        switch level {
        case .danger:
            return "Something on this Mac needs your attention."
        case .watch where !activeAlerts.isEmpty && off > 0:
            return fileChanged ? "A sensitive file changed, and \(offPhrase) off." : "Something changed, and \(offPhrase) off."
        case .watch where !activeAlerts.isEmpty:
            return fileChanged ? "A sensitive file changed since your baseline." : "Something changed since your baseline."
        case .watch:
            return "\(offPhrase.prefix(1).uppercased())\(offPhrase.dropFirst()) switched off."
        case .secure:
            return "Nothing unusual since your baseline."
        }
    }

    /// The detail line under the hero headline.
    var heroMessage: String {
        var parts: [String] = []
        if let a = activeAlerts.first {
            let what = a.subjectPath.map { Fmt.tilde($0) } ?? a.title
            let when = Fmt.date(a.firstSeen).map { " Noticed at \(Fmt.time($0))." } ?? ""
            parts.append(a.kind == "file" ? "\(what) has changed.\(when)" : "\(a.title).\(when)")
        }
        if !failingChecks.isEmpty {
            let names = failingChecks.prefix(2).map(\.name)
            parts.append("\(names.joined(separator: " and ")) \(names.count == 1 ? "is" : "are") at risk.")
        }
        return parts.isEmpty
            ? "Safeguard keeps watching startup items, sensitive files and network activity."
            : parts.joined(separator: " ")
    }

    /// Recent scans and findings as log lines, newest first.
    var logLines: [LogLine] {
        var lines = events.map { LogLine(time: $0.time, level: $0.severity, message: $0.title) }
        for h in (status?.history ?? []).suffix(2) {
            lines.append(LogLine(time: h.time, level: nil, message: "scan complete · \(h.online) apps online"))
        }
        return lines.sorted { $0.time > $1.time }
    }

    static func countWord(_ n: Int) -> String {
        let words = ["no", "one", "two", "three", "four", "five", "six"]
        return words.indices.contains(n) ? words[n] : "\(n)"
    }

    // MARK: lifecycle

    /// System controls (menus, tooltips) follow the look's light or dark.
    func applyAppearance() {
        NSApp.appearance = NSAppearance(named: Theme.skin.dark ? .darkAqua : .aqua)
    }

    func setLook(_ new: Look) {
        guard new != look else { return }
        Theme.look = new
        look = new
        applyAppearance()
        AppDelegate.mainWindow?.backgroundColor = Theme.windowBackground
        persistSettings()
    }

    func start() async {
        applyAppearance()
        if AppStore.snapshotDir == nil {
            adoptLaunchAtLoginOnce()
            startBrowserBridge()
            refreshNotificationPermission()
            requestNotificationPermission()
            restartTimer()
            updateNapGuard()
        }
        await scan()
        await refreshAdvisor()
        if let dir = AppStore.snapshotDir { await Snapshotter.run(store: self, dir: dir) }
    }

    func persistSettings() {
        // Snapshot runs draw with forced settings; they must never write them back.
        guard AppStore.snapshotDir == nil else { return }
        let d = UserDefaults.standard
        d.set(autoScan, forKey: "autoScan")
        d.set(intervalMinutes, forKey: "intervalMinutes")
        d.set(notificationsOn, forKey: "notifications")
        d.set(look.rawValue, forKey: "look")
        d.set(runInBackground, forKey: "runInBackground")
        d.set(showInMenuBar, forKey: "showInMenuBar")
        applyAppearance()
        restartTimer()
        updateNapGuard()
    }

    /// Without this, App Nap stretches the scan timer once the window is closed.
    private func updateNapGuard() {
        let want = runInBackground && autoScan
        if want, napGuard == nil {
            napGuard = ProcessInfo.processInfo.beginActivity(
                options: .userInitiatedAllowingIdleSystemSleep, reason: "Scheduled security scans")
        } else if !want, let token = napGuard {
            ProcessInfo.processInfo.endActivity(token)
            napGuard = nil
        }
    }

    // MARK: window and login item

    func showMainWindow() {
        NSApp.setActivationPolicy(.regular)
        if let window = AppDelegate.mainWindow, window.isVisible || window.isMiniaturized {
            window.deminiaturize(nil)
            window.makeKeyAndOrderFront(nil)
        } else {
            openMainWindowAction?()
        }
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Register once, on first launch, so protection survives a reboot. The
    /// Settings toggle still turns it off and is remembered.
    private func adoptLaunchAtLoginOnce() {
        let d = UserDefaults.standard
        guard d.object(forKey: "launchAtLoginChosen") == nil else {
            launchAtLogin = SMAppService.mainApp.status == .enabled
            return
        }
        d.set(true, forKey: "launchAtLoginChosen")
        guard SMAppService.mainApp.status == .notRegistered else {
            launchAtLogin = SMAppService.mainApp.status == .enabled
            return
        }
        try? SMAppService.mainApp.register()
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func setLaunchAtLogin(_ on: Bool) {
        UserDefaults.standard.set(true, forKey: "launchAtLoginChosen")
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            show(on ? "Safeguard will start when you log in" : "Safeguard won't start at login")
        } catch {
            errorMessage = "Couldn't change the login item: \(error.localizedDescription)"
        }
        if on, SMAppService.mainApp.status == .requiresApproval {
            show("Allow Safeguard in System Settings › General › Login Items")
            SMAppService.openSystemSettingsLoginItems()
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func restartTimer() {
        loopTask?.cancel()
        guard autoScan else { return }
        let ns = UInt64(intervalMinutes) * 60 * 1_000_000_000
        loopTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: ns)
                if Task.isCancelled { break }
                await self?.scan()
            }
        }
    }

    // MARK: actions

    func scan() async {
        guard !scanning else { return }
        scanning = true
        defer { scanning = false }
        do {
            let s = try await Engine.call(ScanStatus.self, ["status"])
            withAnimation(.easeInOut(duration: 0.35)) { status = s }
            events = (try? await Engine.call([ThreatEvent].self, ["events"])) ?? events
            errorMessage = nil
            notify(s.alerts.filter { $0.isNew && !$0.isAcked && $0.severity >= .medium })
            if advisor?.autoDigest == true { await autoDigestIfDue() }
            if screen == .browser { await loadBrowser() }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func setAcknowledged(_ alert: ThreatAlert, _ on: Bool) async {
        await setAcknowledged([alert.id], on)
    }

    /// One engine call for the whole batch; the engine takes any number of ids.
    func setAcknowledged(_ ids: [String], _ on: Bool) async {
        guard !ids.isEmpty else { return }
        do {
            try await Engine.run([on ? "ack" : "unack"] + ids)
            withAnimation {
                for id in ids {
                    if let i = status?.alerts.firstIndex(where: { $0.id == id }) {
                        status?.alerts[i].acked = on
                    }
                }
            }
            if ids.count == 1 {
                show(on ? "Marked as reviewed" : "Moved back to active threats")
            } else {
                show(on ? "\(ids.count) findings marked as reviewed"
                        : "\(ids.count) findings moved back to active")
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func trust(_ path: String, _ on: Bool = true) async {
        do {
            try await Engine.run([on ? "trust" : "untrust", path])
            show(on ? "\(Fmt.programName(path)) is now trusted" : "Removed from trusted programs")
            await scan()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func rebaseline() async {
        do {
            try await Engine.run(["baseline"])
            show("New baseline saved. This is now what normal looks like.")
            await scan()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func setSchedule(_ install: Bool) async {
        do {
            try await Engine.run([install ? "install-schedule" : "uninstall-schedule", "900"])
            status?.scheduleInstalled = install
            show(install ? "Background scans every 15 minutes are on" : "Background scans removed")
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func checkURL(_ raw: String) async {
        let url = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !url.isEmpty else { return }
        checkingURL = true
        defer { checkingURL = false }
        do {
            guard var result = try await Engine.call([URLCheck].self, ["check-url", url]).first else { return }
            result.checkedAt = .now
            withAnimation(.spring(response: 0.4)) {
                urlChecks.removeAll { $0.url == result.url }
                urlChecks.insert(result, at: 0)
                urlChecks = Array(urlChecks.prefix(30))
            }
            if let data = try? JSONEncoder().encode(urlChecks) {
                UserDefaults.standard.set(data, forKey: "urlChecks")
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func clearURLHistory() {
        urlChecks.removeAll()
        UserDefaults.standard.removeObject(forKey: "urlChecks")
    }

    func show(_ message: String) {
        toastTask?.cancel()
        withAnimation(.spring(response: 0.35)) { toast = message }
        toastTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_800_000_000)
            guard !Task.isCancelled else { return }
            withAnimation(.easeOut) { self?.toast = nil }
        }
    }

    func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    func open(_ path: String) {
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }

    // MARK: notifications

    private var canNotify: Bool { Bundle.main.bundleIdentifier != nil && AppStore.snapshotDir == nil }

    func requestNotificationPermission() {
        guard canNotify else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            Task { @MainActor in self.notificationsAllowed = granted }
        }
    }

    func refreshNotificationPermission() {
        guard canNotify else { return }
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            let allowed = settings.authorizationStatus == .authorized
                || settings.authorizationStatus == .provisional
            Task { @MainActor in self.notificationsAllowed = allowed }
        }
    }

    func notify(_ alerts: [ThreatAlert]) {
        guard notificationsOn, canNotify,
              let top = alerts.max(by: { $0.severity < $1.severity }) else { return }
        let content = UNMutableNotificationContent()
        content.title = "Safeguard · \(top.severity.label) threat"
        content.body = top.title + (alerts.count > 1 ? " (+\(alerts.count - 1) more)" : "")
        content.sound = .default
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }

    func sendTestNotification() {
        guard canNotify else { return }
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            Task { @MainActor in
                switch settings.authorizationStatus {
                case .authorized, .provisional:
                    self.deliverTestNotification()
                case .notDetermined:
                    center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
                        Task { @MainActor in
                            self.notificationsAllowed = granted
                            if granted {
                                self.deliverTestNotification()
                            } else {
                                self.show("Notifications were not allowed")
                            }
                        }
                    }
                default:
                    self.notificationsAllowed = false
                    self.show("Notifications are blocked — allow Safeguard in System Settings")
                }
            }
        }
    }

    private func deliverTestNotification() {
        let content = UNMutableNotificationContent()
        content.title = "Safeguard is watching"
        content.body = "This is how threat alerts will look."
        content.sound = .default
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }
}
