import AppKit
import Charts
import SwiftUI

// MARK: - Link Shield

struct LinkShieldView: View {
    @Environment(AppStore.self) private var store
    @State private var input = ""

    var body: some View {
        ScreenScaffold(.links) {
            HStack(alignment: .top, spacing: 12) {
                VStack(spacing: 12) {
                    Tile(padding: 24) {
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Paste a link from an email, text message, WhatsApp or DM")
                                .font(.ui(13.5)).foregroundStyle(Theme.text2)
                            HStack(spacing: 8) {
                                TextField("", text: $input, prompt: Text("https://").foregroundStyle(Theme.text3))
                                    .textFieldStyle(.plain)
                                    .font(.mono(14))
                                    .foregroundStyle(Theme.text)
                                    .padding(.horizontal, 18)
                                    .padding(.vertical, 12)
                                    .background(PillShape().fill(Theme.inset))
                                    .onSubmit(check)
                                Button("Paste and check") {
                                    input = NSPasteboard.general.string(forType: .string) ?? input
                                    check()
                                }
                                .buttonStyle(GhostButtonStyle())
                                Button(action: check) {
                                    HStack(spacing: 6) {
                                        if store.checkingURL { Spinner(color: Theme.accentInk, size: 10) }
                                        Text("Check")
                                    }
                                }
                                .buttonStyle(CoralButtonStyle())
                                .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
                            }
                            Text("Checked entirely on this Mac. The link is never opened or sent anywhere.")
                                .font(.ui(12)).foregroundStyle(Theme.text3)
                        }
                    }
                    .fixedSize(horizontal: false, vertical: true)

                    if let latest = store.urlChecks.first {
                        VerdictTile(check: latest).id(latest.id)
                    }

                    if store.urlChecks.count > 1 {
                        Tile(padding: 22) {
                            VStack(alignment: .leading, spacing: 8) {
                                TileHeader("Earlier checks", caption: "Kept only on this Mac") {
                                    Button("Clear") { store.clearURLHistory() }.buttonStyle(TextLinkStyle(color: Theme.text2))
                                }
                                .padding(.bottom, 4)
                                ForEach(Array(store.urlChecks.dropFirst())) { c in
                                    let look = verdictLook(c.verdict)
                                    HStack(spacing: 12) {
                                        Dot(color: look.color)
                                        Text(c.url).font(.mono(12)).foregroundStyle(Theme.text2)
                                            .lineLimit(1).truncationMode(.middle)
                                        Spacer()
                                        Text(look.short).font(.ui(12.5, 600)).foregroundStyle(look.color)
                                        if let d = c.checkedAt {
                                            Text(Fmt.relative(d)).font(.ui(12)).foregroundStyle(Theme.text3)
                                                .frame(width: 96, alignment: .trailing)
                                        }
                                    }
                                    .insetRow()
                                    .onTapGesture { input = c.url; check() }
                                }
                            }
                        }
                        .fixedSize(horizontal: false, vertical: true)
                    }
                }
                PhishingNotes().frame(width: 360).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func check() {
        let value = input
        Task { await store.checkURL(value) }
    }
}

func verdictLook(_ verdict: String) -> (color: Color, fill: Color, ink: Color, title: String, short: String) {
    let filled = Theme.skin.heroFilled
    switch verdict {
    case "dangerous":
        return (Theme.red, ThreatLevel.danger.hero, ThreatLevel.danger.heroInk, "Don’t open this link.", "Dangerous")
    case "suspicious":
        return (Theme.amber, filled ? Theme.warnFill : Theme.amber, filled ? Theme.warnInk : Theme.text,
                "Treat this link with suspicion.", "Suspicious")
    default:
        return (Theme.green, ThreatLevel.secure.hero, ThreatLevel.secure.heroInk, "No red flags found.", "Clear")
    }
}

struct VerdictTile: View {
    let check: URLCheck

    var body: some View {
        let look = verdictLook(check.verdict)
        VStack(spacing: 12) {
            Tile(padding: 26, fill: look.fill, hero: true) {
                VStack(alignment: .leading, spacing: 12) {
                    HeroBadge(text: look.short, color: look.fill, ink: look.ink)
                    Text(look.title).font(.display(34)).foregroundStyle(look.ink)
                    Text(check.url).font(.mono(13)).foregroundStyle(look.ink.opacity(0.75))
                        .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                    Text(check.verdict == "clear"
                         ? "Not a guarantee. If a message pressures you to act fast, type the site's address yourself."
                         : "If it claims to be from your bank or a service you use, open their app or type their address yourself.")
                        .font(.ui(13)).foregroundStyle(look.ink.opacity(0.8))
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 4)
                }
            }
            .fixedSize(horizontal: false, vertical: true)

            if !check.findings.isEmpty {
                Tile(padding: 22) {
                    VStack(alignment: .leading, spacing: 8) {
                        TileHeader("Why").padding(.bottom, 4)
                        ForEach(check.findings.sorted { $0.severity > $1.severity }, id: \.self) { f in
                            HStack(alignment: .firstTextBaseline, spacing: 14) {
                                Text(f.severity.label).font(.ui(12.5, 600)).foregroundStyle(f.severity.color).labelCase()
                                    .frame(width: 64, alignment: .leading)
                                Text(f.message).font(.ui(13.5)).foregroundStyle(Theme.text)
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer(minLength: 0)
                            }
                            .insetRow()
                        }
                    }
                }
                .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct PhishingNotes: View {
    private let notes: [(String, String)] = [
        ("Good writing proves nothing.",
         "AI writes fluent, personal-sounding scams. Judge the link and the request, not the grammar."),
        ("Urgency is the attack.",
         "\"Your account closes in one hour\" exists to stop you thinking. Slow down."),
        ("Read the real domain.",
         "It's the part just before the first single slash: paypal.com.evil.xyz belongs to evil.xyz."),
        ("Voices can be cloned.",
         "A call from family asking for money? Use a code word, or hang up and call them back."),
        ("Never paste commands a site gives you.",
         "\"Press ⌘V in Terminal to verify you're human\" installs malware. Every time."),
        ("Let your password manager judge.",
         "It won't autofill on a fake domain. If it doesn't offer your login, stop."),
    ]

    var body: some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Spotting AI-written phishing").font(.display(20)).foregroundStyle(Theme.text)
                ForEach(Array(notes.enumerated()), id: \.offset) { i, n in
                    HStack(alignment: .firstTextBaseline, spacing: 14) {
                        Text(String(format: "%02d", i + 1)).font(.display(15, 700)).foregroundStyle(Theme.accentText)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(n.0).font(.ui(13.5, 600)).foregroundStyle(Theme.text)
                            Text(n.1).font(.ui(12.5)).foregroundStyle(Theme.text2).lineSpacing(2)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Activity

struct ActivityView: View {
    @Environment(AppStore.self) private var store

    private struct Bar: Identifiable {
        let id: String
        let index: Int
        let severity: String
        let count: Int
    }

    var body: some View {
        let history = Array((store.status?.history ?? []).suffix(60))
        let bars = history.enumerated().flatMap { i, p in
            [Bar(id: "\(i)h", index: i, severity: "High", count: p.high),
             Bar(id: "\(i)m", index: i, severity: "Medium", count: p.medium),
             Bar(id: "\(i)l", index: i, severity: "Low", count: p.low)]
        }
        let groups = Dictionary(grouping: store.events) { String($0.time.prefix(10)) }
            .sorted { $0.key > $1.key }

        ScreenScaffold(.activity) {
            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    StatTile("Scans recorded", value: "\(store.status?.history.count ?? 0)")
                    StatTile("Findings logged", value: "\(store.events.count)")
                    StatTile("High severity, ever", value: "\(store.events.filter { $0.severity == .high }.count)",
                             captionColor: Theme.red)
                    StatTile("Baseline taken",
                             value: Fmt.date(store.status?.baseline.taken).map(Fmt.relativeShort) ?? "—")
                }
                .frame(height: 132)

                Tile(padding: 22) {
                    VStack(alignment: .leading, spacing: 18) {
                        TileHeader("Findings per scan", caption: "Unreviewed findings each time Safeguard looked") {
                            HStack(spacing: 14) {
                                Legend(color: Theme.red, label: "High")
                                Legend(color: Theme.amber, label: "Medium")
                                Legend(color: Theme.blue, label: "Low")
                            }
                        }
                        if history.count < 2 {
                            Text("The chart fills in as Safeguard scans.").font(.ui(13)).foregroundStyle(Theme.text3)
                                .frame(maxWidth: .infinity, minHeight: 170)
                        } else {
                            Chart(bars) { b in
                                BarMark(x: .value("Scan", b.index), y: .value("Findings", b.count), width: 9)
                                    .foregroundStyle(by: .value("Severity", b.severity))
                                    .cornerRadius(2)
                            }
                            .chartForegroundStyleScale(["High": Theme.red, "Medium": Theme.amber, "Low": Theme.blue])
                            .chartLegend(.hidden)
                            .chartXScale(domain: -0.5...(Double(history.count) - 0.5))
                            .chartXAxis {
                                AxisMarks(values: .automatic(desiredCount: 6)) { value in
                                    if let i = value.as(Int.self), i >= 0, i < history.count {
                                        AxisValueLabel {
                                            Text(Fmt.time(history[i].date)).font(.ui(11)).foregroundStyle(Theme.text3)
                                        }
                                    }
                                }
                            }
                            .chartYAxis {
                                AxisMarks(position: .leading, values: .automatic(desiredCount: 4)) { _ in
                                    AxisGridLine(stroke: StrokeStyle(lineWidth: 1)).foregroundStyle(Theme.line)
                                    AxisValueLabel().font(.ui(11)).foregroundStyle(Theme.text3)
                                }
                            }
                            .chartYScale(domain: 0...max(4, (history.map { $0.high + $0.medium + $0.low }.max() ?? 0) + 1))
                            .frame(height: 180)
                        }
                    }
                }
                .fixedSize(horizontal: false, vertical: true)

                Tile(padding: 22) {
                    VStack(alignment: .leading, spacing: 10) {
                        TileHeader("Fixes applied", caption: "Every change Safeguard made carries its own undo") {
                            Button("Refresh") { Task { await store.loadFixRecords() } }
                                .buttonStyle(TextLinkStyle(color: Theme.text3))
                        }
                        if store.fixRecords.isEmpty {
                            EmptyNote(symbol: "wrench.and.screwdriver", title: "No fixes yet",
                                      message: "When you approve a fix from the Advisor, it appears here with its record.")
                        }
                        ForEach(store.fixRecords) { record in
                            HStack(spacing: 12) {
                                Dot(color: record.undone == true ? Theme.text3
                                            : record.verified == true ? Theme.green
                                            : record.rolledBack == true ? Theme.amber : Theme.blue)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(record.title).font(.ui(13.5, 500))
                                        .foregroundStyle(record.undone == true ? Theme.text3 : Theme.text)
                                    HStack(spacing: 8) {
                                        Text(record.action).font(.mono(10.5)).foregroundStyle(Theme.text3)
                                        if let at = record.at, let date = Fmt.date(at) {
                                            Text(Fmt.dateTime(date)).font(.ui(11)).foregroundStyle(Theme.text3)
                                        }
                                        if record.verified == true {
                                            Text("verified").font(.ui(11)).foregroundStyle(Theme.green)
                                        } else if record.rolledBack == true {
                                            Text("rolled back").font(.ui(11)).foregroundStyle(Theme.amber)
                                        }
                                    }
                                }
                                Spacer()
                                if record.undone == true {
                                    Text("undone").font(.ui(11)).foregroundStyle(Theme.text3)
                                } else {
                                    Button("Undo") { Task { await store.undoFix(record.id) } }
                                        .buttonStyle(TextLinkStyle(color: Theme.text2))
                                        .disabled(store.fixing)
                                }
                            }
                            .insetRow()
                        }
                    }
                }
                .fixedSize(horizontal: false, vertical: true)

                Tile(padding: 22) {
                    VStack(alignment: .leading, spacing: 10) {
                        TileHeader("Event log", caption: "Each finding, the first time Safeguard saw it")
                        if groups.isEmpty {
                            EmptyNote(symbol: "list.bullet", title: "No events yet",
                                      message: "Findings are logged here the moment Safeguard first notices them.")
                        }
                        ForEach(groups, id: \.key) { day, items in
                            Text(Fmt.date(day + "T00:00:00").map(Fmt.day) ?? day)
                                .font(.display(16, 600)).foregroundStyle(Theme.text)
                                .padding(.top, 8)
                            ForEach(Array(items.enumerated()), id: \.offset) { _, e in
                                HStack(alignment: .firstTextBaseline, spacing: 16) {
                                    Text(Fmt.date(e.time).map(Fmt.time) ?? "")
                                        .font(.ui(12.5, 500)).monospacedDigit().foregroundStyle(Theme.text3)
                                        .frame(width: 70, alignment: .leading)
                                    Text(e.severity.label).font(.ui(12.5, 600)).foregroundStyle(e.severity.color).labelCase()
                                        .frame(width: 64, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(e.title).font(.ui(13.5, 500)).foregroundStyle(Theme.text)
                                        Text(e.detail.split(separator: "\n").first.map(String.init) ?? "")
                                            .font(.mono(11)).foregroundStyle(Theme.text3)
                                            .lineLimit(1).truncationMode(.middle)
                                    }
                                }
                                .insetRow()
                            }
                        }
                    }
                }
            }
        }
        .task { await store.loadFixRecords() }
    }
}

struct Legend: View {
    let color: Color
    let label: String

    var body: some View {
        HStack(spacing: 6) {
            Dot(color: color, size: 8)
            Text(label).font(.ui(12)).foregroundStyle(Theme.text2)
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let s = store.status!
        ScreenScaffold(.settings) {
            VStack(spacing: Theme.skin.gap) {
            SettingsTile(icon: "paintbrush", title: "Appearance", caption: "Seven looks. Pick one and the whole app changes at once.") {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 178), spacing: 10, alignment: .top)], spacing: 10) {
                    ForEach(Look.allCases) { look in
                        LookCard(look: look, selected: store.look == look) { store.setLook(look) }
                    }
                }
            }
            AdvisorSettings()
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 12, alignment: .top),
                                GridItem(.flexible(), spacing: 12, alignment: .top)], spacing: 12) {
                SettingsTile(icon: "timer", title: "Scanning", caption: "Whenever Safeguard is running") {
                    SettingRow(title: "Scan automatically", detail: "Re-check everything on a timer") {
                        Toggle("", isOn: Binding(get: { store.autoScan },
                                                 set: { store.autoScan = $0; store.persistSettings() }))
                            .toggleStyle(SwitchStyle()).labelsHidden()
                    }
                    SettingRow(title: "How often", detail: "Shorter catches changes sooner") {
                        Segmented(options: [(5, "5 min"), (15, "15"), (30, "30"), (60, "1 hr")],
                                  selection: Binding(get: { store.intervalMinutes },
                                                     set: { store.intervalMinutes = $0; store.persistSettings() }))
                            .opacity(store.autoScan ? 1 : 0.4)
                            .disabled(!store.autoScan)
                    }
                }

                SettingsTile(icon: "safari", title: "Browser history",
                             caption: "Sites are read from local browser databases. Nothing leaves this Mac.") {
                    SettingRow(title: "Keep visits", detail: "Older entries are deleted automatically") {
                        Segmented(options: [(7, "7 days"), (30, "30"), (90, "90"), (365, "1 year")],
                                  selection: Binding(get: { store.browser?.retentionDays ?? 90 },
                                                     set: { days in
                                                         Task { await store.saveBrowserRetention(days) }
                                                     }))
                    }
                    SettingRow(title: "Keep requests", detail: "Raw request records from the extension") {
                        Segmented(options: [(1, "1 day"), (7, "7 days"), (30, "30"), (90, "90")],
                                  selection: Binding(get: { store.browser?.requestRetentionDays ?? 7 },
                                                     set: { days in
                                                         Task { await store.saveBrowserRequestRetention(days) }
                                                     }))
                    }
                    SettingRow(title: "Live monitoring",
                               detail: store.browser?.bridge?.service == "safeguard"
                                   ? "Extension bridge is running" : "Bridge is starting or unavailable") {
                        Button("Install extension") { Task { await store.installBrowserExtension() } }
                            .buttonStyle(GhostButtonStyle(compact: true))
                    }
                    SettingRow(title: "Import now", detail: "Read new visits from Safari, Chrome and Firefox") {
                        Button("Import") { Task { await store.importBrowserNow() } }
                            .buttonStyle(GhostButtonStyle(compact: true))
                            .disabled(store.browserLoading)
                    }
                    SettingRow(title: "Clear Safeguard's copy",
                               detail: "Does not touch Safari's or Chrome's own history") {
                        Button("Clear") { Task { await store.clearBrowserHistory() } }
                            .buttonStyle(TextLinkStyle(color: Theme.text3))
                    }
                }
                SettingsTile(icon: "bell", title: "Alerts", caption: "How Safeguard gets your attention") {
                    SettingRow(title: "Notify me about new threats", detail: "Medium and high, once per finding") {
                        Toggle("", isOn: Binding(get: { store.notificationsOn },
                                                 set: { store.notificationsOn = $0; store.persistSettings() }))
                            .toggleStyle(SwitchStyle()).labelsHidden()
                    }
                    SettingRow(title: "Test notification", detail: "Check that alerts reach you") {
                        Button("Send") { store.sendTestNotification() }.buttonStyle(GhostButtonStyle(compact: true))
                    }
                    if store.notificationsAllowed == false {
                        SettingRow(title: "Notifications are blocked",
                                   detail: "Allow Safeguard in System Settings › Notifications to see alerts.") {
                            Button("Open Settings") {
                                if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") {
                                    NSWorkspace.shared.open(url)
                                }
                            }
                            .buttonStyle(GhostButtonStyle(compact: true))
                        }
                    }
                }

                SettingsTile(icon: "moon.stars", title: "Background protection", caption: "Keep watching with the window closed") {
                    SettingRow(title: "Keep running in the background",
                               detail: "Closing the window leaves Safeguard scanning from the menu bar. Quit it from the menu bar panel.") {
                        Toggle("", isOn: Binding(get: { store.runInBackground },
                                                 set: { store.runInBackground = $0; store.persistSettings() }))
                            .toggleStyle(SwitchStyle()).labelsHidden()
                    }
                    SettingRow(title: "Show in the menu bar", detail: "Status, score and quick actions one click away") {
                        Toggle("", isOn: Binding(get: { store.showInMenuBar },
                                                 set: { store.showInMenuBar = $0; store.persistSettings() }))
                            .toggleStyle(SwitchStyle()).labelsHidden()
                    }
                    SettingRow(title: "Open at login", detail: "Starts quietly in the menu bar when you log in") {
                        Toggle("", isOn: Binding(get: { store.launchAtLogin },
                                                 set: { store.setLaunchAtLogin($0) }))
                            .toggleStyle(SwitchStyle()).labelsHidden()
                    }
                    SettingRow(title: s.scheduleInstalled ? "Even after you quit: on" : "Even after you quit: off",
                               detail: "A launch agent scans every 15 minutes when the app isn't running. Safeguard adds it to your baseline so it doesn't flag itself.") {
                        Button(s.scheduleInstalled ? "Turn off" : "Turn on") {
                            let install = !s.scheduleInstalled
                            store.confirm = ConfirmRequest(
                                title: install ? "Turn on background protection?" : "Turn off background protection?",
                                message: install
                                    ? "Safeguard will add a launch agent so scans keep running every 15 minutes, even after you quit the app."
                                    : "Background scans will stop. Safeguard will only scan while this window is open.",
                                action: install ? "Turn on" : "Turn off") { await store.setSchedule(install) }
                        }
                        .buttonStyle(LightButtonStyle(compact: true))
                    }
                }

                SettingsTile(icon: "camera.viewfinder", title: "Baseline", caption: "Safeguard's picture of normal") {
                    SettingRow(title: "Taken \(Fmt.date(s.baseline.taken).map(Fmt.dateTime) ?? "—")",
                               detail: "After you install software or edit config on purpose, save a new baseline so those changes stop showing up.") {
                        Button("Accept current") {
                            store.confirm = ConfirmRequest(
                                title: "Save a new baseline?",
                                message: "Everything on your Mac right now becomes the new normal, and current findings are cleared. Review your threats first.",
                                action: "Save baseline", destructive: true) { await store.rebaseline() }
                        }
                        .buttonStyle(GhostButtonStyle(compact: true))
                    }
                }

                SettingsTile(icon: "hand.thumbsup", title: "Trusted programs", caption: "Left out of network alerts") {
                    let trusted = s.allowlist.paths + s.allowlist.processes
                    if trusted.isEmpty {
                        Text("None yet. Trust a program from its finding on the Threats screen.")
                            .font(.ui(13)).foregroundStyle(Theme.text2).insetRow()
                    }
                    ForEach(Array(trusted.enumerated()), id: \.offset) { _, p in
                        HStack(spacing: 10) {
                            ProgramIcon(path: p, size: 24)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(Fmt.programName(p)).font(.ui(13, 600)).foregroundStyle(Theme.text)
                                PathText(p, size: 10.5)
                            }
                            Spacer()
                            Button("Remove") { Task { await store.trust(p, false) } }.buttonStyle(TextLinkStyle())
                        }
                        .insetRow()
                    }
                }

                SettingsTile(icon: "externaldrive", title: "Data", caption: "Everything stays on this Mac") {
                    PathSetting(title: "Data folder", path: s.dataDir) { store.open(s.dataDir) }
                    PathSetting(title: "Latest report", path: s.report) { store.open(s.report) }
                    PathSetting(title: "Detection engine", path: Engine.scriptPath ?? "missing") {
                        if let p = Engine.scriptPath { store.reveal(p) }
                    }
                }
            }
            }
        }
    }
}

struct SettingsTile<Content: View>: View {
    let icon: String
    let title: String
    let caption: String
    @ViewBuilder let content: Content

    var body: some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    Image(systemName: icon).font(.system(size: 15)).foregroundStyle(Theme.text)
                        .frame(width: 38, height: 38).background(RoundShape().fill(Theme.inset))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title).font(.display(18, 600)).foregroundStyle(Theme.text)
                        Text(caption).font(.ui(12.5)).foregroundStyle(Theme.text3)
                    }
                }
                .padding(.bottom, 6)
                content
            }
        }
    }
}

struct SettingRow<Control: View>: View {
    let title: String
    let detail: String
    @ViewBuilder let control: Control

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.ui(13.5, 500)).foregroundStyle(Theme.text)
                Text(detail).font(.ui(12)).foregroundStyle(Theme.text3)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            control
        }
        .insetRow(padding: EdgeInsets(top: 12, leading: 16, bottom: 12, trailing: 12))
    }
}

struct PathSetting: View {
    let title: String
    let path: String
    let action: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.ui(13, 500)).foregroundStyle(Theme.text)
                PathText(path, size: 10.5)
            }
            Spacer()
            Button("Open", action: action).buttonStyle(TextLinkStyle())
        }
        .insetRow()
    }
}

/// A selectable preview of one look. The preview is drawn from that look's own style sheet.
struct LookCard: View {
    let look: Look
    let selected: Bool
    let action: () -> Void
    @State private var hover = false

    private var preview: some View {
        let s = look.skin
        func c(_ h: UInt32) -> Color { Color(hex: h) }
        let r: CGFloat = 5 * s.radiusScale
        let border = s.panelBorder.map { c($0) }
        func panel(_ w: CGFloat, _ h: CGFloat, fill: UInt32? = nil, hero: Bool = false) -> some View {
            ZStack {
                if s.panelKind == .filled {
                    if s.panelShadow > 0 {
                        RoundedRectangle(cornerRadius: r).fill(c(0x111111)).offset(x: 2, y: 2)
                    }
                    RoundedRectangle(cornerRadius: r).fill(c(fill ?? s.tile))
                    if let b = border { RoundedRectangle(cornerRadius: r).strokeBorder(b, lineWidth: s.panelShadow > 0 ? 1.2 : 0.8) }
                } else {
                    Rectangle().fill(.clear).overlay(alignment: .top) { Rectangle().fill(c(s.line)).frame(height: 1) }
                }
            }
            .frame(width: w, height: h)
        }
        let heroFill = s.hero[1]
        return ZStack(alignment: .topLeading) {
            c(s.bg)
            // navigation
            switch s.chrome {
            case .rail:
                VStack(spacing: 4) {
                    ForEach(0..<4, id: \.self) { i in
                        RoundedRectangle(cornerRadius: 3).fill(c(i == 0 ? s.text : s.tile)).frame(width: 11, height: 11)
                    }
                }.offset(x: 7, y: 9)
            case .ops:
                Rectangle().fill(c(s.accent)).frame(width: 26, height: 3).offset(x: 6, y: 5)
                Rectangle().fill(c(s.line)).frame(height: 1).offset(y: 12)
                VStack(alignment: .leading, spacing: 4) {
                    Rectangle().fill(c(s.accent)).frame(width: 22, height: 5)
                    Rectangle().fill(c(s.edge)).frame(width: 22, height: 3)
                    Rectangle().fill(c(s.edge)).frame(width: 22, height: 3)
                }.offset(x: 6, y: 20)
            case .sidebar:
                if look == .brutal || look == .hardware {
                    panel(30, 80).offset(x: 4, y: 4)
                } else {
                    Rectangle().fill(c(s.line)).frame(width: 1, height: 100).offset(x: 34)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Rectangle().fill(c(look == .swiss ? s.text : s.accent)).frame(width: 18, height: 4)
                    ForEach(0..<3, id: \.self) { _ in Rectangle().fill(c(s.dim)).frame(width: 18, height: 3) }
                }.offset(x: 8, y: 10)
            case .topbar:
                HStack(spacing: 3) {
                    Capsule().fill(c(s.text)).frame(width: 18, height: 6)
                    ForEach(0..<4, id: \.self) { _ in Capsule().strokeBorder(c(s.line), lineWidth: 1).frame(width: 14, height: 6) }
                }.offset(x: 28, y: 6)
            }
            // page
            let x0: CGFloat = s.chrome == .rail ? 26 : s.chrome == .topbar ? 8 : 42
            let y0: CGFloat = s.chrome == .topbar ? 20 : s.chrome == .ops ? 18 : 8
            if s.heroFilled {
                panel(70, 46, fill: heroFill).offset(x: x0, y: y0)
            } else if look == .dotmatrix {
                Text("78").font(Typeface.font(.doto, 38, 900)).foregroundStyle(c(s.text)).offset(x: x0, y: y0 - 6)
            } else if look == .swiss {
                Text("78").font(Typeface.font(.interTight, 40, 900)).foregroundStyle(c(s.text)).offset(x: x0, y: y0 - 8)
            } else if look == .hardware {
                RoundedRectangle(cornerRadius: 2).fill(c(0xB7C0A1)).frame(width: 58, height: 30).offset(x: x0 + 6, y: y0 + 8)
            } else {
                panel(70, 46).offset(x: x0, y: y0)
                if look == .graphite {
                    Circle().trim(from: 0, to: 0.78).stroke(c(s.accent), lineWidth: 4).rotationEffect(.degrees(-90))
                        .frame(width: 30, height: 30).offset(x: x0 + 8, y: y0 + 8)
                } else {
                    Rectangle().fill(c(s.hero[1])).frame(width: 30, height: 5).offset(x: x0 + 8, y: y0 + 8)
                }
            }
            panel(32, 21).offset(x: x0 + 76, y: y0)
            panel(32, 21).offset(x: x0 + 76, y: y0 + 25)
            panel(52, 26).offset(x: x0, y: y0 + 54)
            panel(52, 26).offset(x: x0 + 56, y: y0 + 54)
        }
        .frame(height: 96)
        .clipShape(RoundedRectangle(cornerRadius: Theme.corner(10), style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Theme.corner(10), style: .continuous)
            .strokeBorder(Theme.line.opacity(0.9), lineWidth: 1))
    }

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 10) {
                preview
                HStack(spacing: 8) {
                    Text(look.letter).font(.tag(11, 600)).foregroundStyle(Theme.text3)
                    Text(look.title).font(.ui(13.5, 600)).foregroundStyle(Theme.text).labelCase(tracking: 1, control: true)
                    Spacer()
                    if selected {
                        Image(systemName: "checkmark").font(.system(size: 10.5, weight: .bold)).foregroundStyle(Theme.accentText)
                    }
                }
                Text(look.blurb).font(.ui(12)).foregroundStyle(Theme.text3)
                    .multilineTextAlignment(.leading).fixedSize(horizontal: false, vertical: true)
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .background(RoundedRectangle(cornerRadius: Theme.corner(16), style: .continuous)
                .fill(hover ? Theme.insetHover : Theme.inset))
            .overlay(RoundedRectangle(cornerRadius: Theme.corner(16), style: .continuous)
                .strokeBorder(selected ? Theme.accentText : .clear, lineWidth: 2))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .accessibilityLabel("\(look.title) look")
    }
}
