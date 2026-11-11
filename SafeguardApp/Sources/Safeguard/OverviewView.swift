import SwiftUI

struct OverviewView: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        ScreenScaffold(.overview) {
            switch Theme.look {
            case .bento: bentoLayout
            case .fieldops: opsLayout
            default: DesignOverview()
            }
        }
    }

    /// Field Ops: status block, one stat strip, then log and matrix side by side.
    private var opsLayout: some View {
        VStack(spacing: 18) {
            OpsStatusBlock()
            OpsStatStrip()
            HStack(alignment: .top, spacing: 18) {
                OpsEventLog().frame(maxWidth: .infinity)
                OpsProtectionMatrix().frame(maxWidth: .infinity)
            }
            .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: 18) {
                FixTheseTile()
                QuickLinkTile()
            }
            .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: 18) {
                RecentFindingsTile()
                WatchZonesTile()
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var bentoLayout: some View {
            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    HeroTile().frame(maxWidth: .infinity)
                    VStack(spacing: 12) {
                        HStack(spacing: 12) {
                            ThreatCountTile()
                            ProtectionCountTile()
                        }
                        HStack(spacing: 12) {
                            AppsOnlineTile()
                            PortsTile()
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                .frame(height: 330)

                HStack(alignment: .top, spacing: 12) {
                    FixTheseTile()
                    QuickLinkTile()
                }
                .fixedSize(horizontal: false, vertical: true)

                HStack(alignment: .top, spacing: 12) {
                    RecentFindingsTile()
                    WatchZonesTile()
                }
                .fixedSize(horizontal: false, vertical: true)
            }
    }
}

// MARK: - Hero

struct HeroTile: View {
    @Environment(AppStore.self) private var store

    private func heroText(_ level: ThreatLevel, headlineSize: CGFloat, showMessage: Bool) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(store.headline)
                .font(.display(headlineSize))
                .foregroundStyle(level.heroInk)
                .lineSpacing(-2)
                .fixedSize(horizontal: false, vertical: true)
            if showMessage {
                Text(store.heroMessage)
                    .font(.ui(13.5))
                    .foregroundStyle(level.heroInkSoft)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HeroActions(level: level).padding(.top, 6)
        }
    }

    var body: some View {
        let level = store.level
        Tile(padding: 26, fill: level.hero, hero: true) {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    HeroBadge(text: level.badge, color: level.hero, ink: level.heroInk)
                    Spacer()
                    Text("Security score").font(.ui(13, 500)).foregroundStyle(level.heroInk)
                }
                Spacer(minLength: 12)
                HStack(alignment: .bottom, spacing: 16) {
                    // Smaller windows get a smaller headline, then lose the detail line, instead of clipping.
                    ViewThatFits(in: .vertical) {
                        heroText(level, headlineSize: 29, showMessage: true)
                        heroText(level, headlineSize: 24, showMessage: true)
                        heroText(level, headlineSize: 24, showMessage: false)
                    }
                    .frame(maxWidth: 360, alignment: .leading)
                    Spacer(minLength: 0)
                    Text("\(store.score)")
                        .font(.figure(160, 800))
                        .tracking(-8)
                        .foregroundStyle(level.heroInk)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                        .padding(.bottom, -22)
                        .contentTransition(.numericText())
                }
            }
        }
    }
}

// MARK: - Stat tiles

struct ThreatCountTile: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let top = store.activeAlerts.first
        Tile {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Active threats").font(.ui(13)).foregroundStyle(Theme.text2)
                    Spacer()
                    if let top { Text(top.severity.label).font(.ui(12, 500)).foregroundStyle(top.severity.color).labelCase() }
                }
                Spacer(minLength: 10)
                Text("\(store.activeAlerts.count)").font(.figure(46)).foregroundStyle(Theme.text)
                Text(top.map { $0.title } ?? "Nothing since your baseline")
                    .font(.ui(12.5)).foregroundStyle(Theme.text2).lineLimit(1)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { store.screen = .threats }
    }
}

struct ProtectionCountTile: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let on = store.checks.filter(\.passed).count
        Tile {
            VStack(alignment: .leading, spacing: 0) {
                Text("Protections on").font(.ui(13)).foregroundStyle(Theme.text2)
                Spacer(minLength: 10)
                HStack(alignment: .firstTextBaseline, spacing: 0) {
                    Text("\(on)").font(.figure(46)).foregroundStyle(Theme.text)
                    Text("/\(store.checks.count)").font(.figure(46)).foregroundStyle(Theme.dim)
                }
                SegmentBar(colors: store.checks.map { $0.passed ? Theme.text : $0.failed ? Theme.amber : Theme.dim })
                    .padding(.top, 6)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { store.screen = .protection }
    }
}

struct AppsOnlineTile: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let s = store.status!
        let links = s.connections.reduce(0) { $0 + $1.remotes.count }
        let spark = Array(s.history.suffix(14).map(\.online))
        StatTile("Apps online", value: "\(s.connections.count)", caption: "\(links) links",
                 action: { store.screen = .network }) {
            if spark.count > 1 { Spark(values: spark, highlight: Theme.text2) }
        }
    }
}

struct PortsTile: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let s = store.status!
        StatTile("Open ports", value: "\(s.listening.count)",
                 caption: "\(s.listening.filter(\.exposed).count) reachable",
                 action: { store.screen = .network })
    }
}

// MARK: - Fix these

struct FixTheseTile: View {
    @Environment(AppStore.self) private var store

    private func phrase(_ c: PostureCheck) -> String {
        switch c.key {
        case "com.openssh.sshd": "Remote Login (SSH) is on"
        case "com.apple.screensharing": "Screen Sharing is on"
        case "guest": "Guest account is on"
        case "sshkeys": "An SSH key has no passphrase"
        default: "\(c.name) is off"
        }
    }

    var body: some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 10) {
                TileHeader("Fix these") {
                    Button("All protections") { store.screen = .protection }.buttonStyle(TextLinkStyle())
                }
                if store.failingChecks.isEmpty {
                    HStack(spacing: 10) {
                        Dot(color: Theme.green)
                        Text("Every protection Safeguard checks is on.").font(.ui(13.5)).foregroundStyle(Theme.text2)
                    }
                    .insetRow()
                } else {
                    ForEach(store.failingChecks.prefix(3)) { c in
                        HStack(spacing: 12) {
                            Dot(color: c.severity == .high ? Theme.red : Theme.amber)
                            Text(phrase(c)).font(.ui(13.5)).foregroundStyle(Theme.text)
                            Spacer()
                            if let link = CheckMeta.for(c.key).settingsURL, let url = URL(string: link) {
                                Button("Open Settings") { NSWorkspace.shared.open(url) }
                                    .buttonStyle(LightButtonStyle(compact: true))
                            } else {
                                Button("How to fix") { store.screen = .protection }
                                    .buttonStyle(LightButtonStyle(compact: true))
                            }
                        }
                        .insetRow(padding: EdgeInsets(top: 9, leading: 14, bottom: 9, trailing: 10))
                    }
                }
            }
        }
    }
}

// MARK: - Link Shield shortcut

struct QuickLinkTile: View {
    @Environment(AppStore.self) private var store
    @State private var input = ""

    var body: some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 12) {
                TileHeader("Link Shield") {
                    Text("Checked on this Mac").font(.ui(12.5)).foregroundStyle(Theme.text3)
                }
                Text("Paste a link from a message before you open it").font(.ui(12.5)).foregroundStyle(Theme.text2)
                HStack(spacing: 8) {
                    TextField("", text: $input, prompt: Text("https://").foregroundStyle(Theme.text3))
                        .textFieldStyle(.plain)
                        .font(.ui(13.5))
                        .foregroundStyle(Theme.text)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 11)
                        .background(PillShape().fill(Theme.inset))
                        .onSubmit(check)
                    Button("Check", action: check)
                        .buttonStyle(CoralButtonStyle())
                        .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }

    private func check() {
        let value = input
        Task {
            await store.checkURL(value)
            store.screen = .links
        }
    }
}

// MARK: - Findings and zones

struct RecentFindingsTile: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 10) {
                TileHeader("Recent findings") {
                    if !store.activeAlerts.isEmpty {
                        Button("View all") { store.screen = .threats }.buttonStyle(TextLinkStyle())
                    }
                }
                if store.activeAlerts.isEmpty {
                    EmptyNote(symbol: "checkmark.shield", title: "All clear",
                              message: "New startup items, file changes and suspicious connections will appear here.")
                } else {
                    ForEach(store.activeAlerts.prefix(4)) { a in
                        ThreatRow(alert: a, selected: false)
                            .onTapGesture {
                                store.selectedAlertID = a.id
                                store.screen = .threats
                            }
                    }
                }
            }
        }
    }
}

struct ThreatRow: View {
    let alert: ThreatAlert
    let selected: Bool

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Dot(color: alert.severity.color, size: 9)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 7) {
                    Text(alert.title).font(.ui(13.5, 600))
                        .foregroundStyle(alert.isAcked ? Theme.text3 : Theme.text)
                        .lineLimit(1)
                    if alert.isNew { Pill("New", color: Theme.accentText, fill: Theme.accent.opacity(0.14)) }
                }
                Text(alert.detail.split(separator: "\n").first.map(String.init) ?? "")
                    .font(.mono(11)).foregroundStyle(Theme.text3)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 10)
            VStack(alignment: .trailing, spacing: 3) {
                Text(alert.severity.label).font(.ui(12, 600)).foregroundStyle(alert.severity.color).labelCase()
                Text(alert.kindLabel).font(.ui(11.5)).foregroundStyle(Theme.text3)
            }
        }
        .insetRow(selected: selected)
    }
}

struct WatchZonesTile: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let s = store.status!
        let newItems = s.launchItems.filter { !$0.known || $0.changed }.count
        let present = s.files.filter { $0.state != "absent" }
        let changed = present.filter { ["modified", "created", "deleted"].contains($0.state) }.count
        let rows: [(String, String, String?)] = [
            ("Startup items", "\(s.launchItems.count)", newItems > 0 ? "\(newItems) new" : nil),
            ("Sensitive files intact", "\(present.count - changed)/\(present.count)", changed > 0 ? "\(changed) changed" : nil),
            ("System extensions", "\(s.systemExtensions.count)", nil),
            ("Scheduled jobs", "\(s.crontab.count)", nil),
        ]
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 10) {
                TileHeader("Watch zones") {
                    Button("Startup items") { store.screen = .startup }.buttonStyle(TextLinkStyle())
                }
                ForEach(Array(rows.enumerated()), id: \.offset) { _, r in
                    HStack(spacing: 10) {
                        Text(r.0).font(.ui(13.5)).foregroundStyle(Theme.text2)
                        Spacer()
                        if let note = r.2 { Text(note).font(.ui(12, 600)).foregroundStyle(Theme.amber) }
                        Text(r.1).font(.figure(17, 600)).foregroundStyle(Theme.text)
                    }
                    .insetRow()
                    .onTapGesture { store.screen = .startup }
                }
            }
        }
    }
}

/// The buttons under a hero headline: review the finding, fix settings, or open the report.
struct HeroActions: View {
    @Environment(AppStore.self) private var store
    let level: ThreatLevel

    var body: some View {
        HStack(spacing: 8) {
            if !store.activeAlerts.isEmpty {
                Button("Review finding") {
                    store.selectedAlertID = store.activeAlerts.first?.id
                    store.screen = .threats
                }
                .buttonStyle(HeroButtonStyle(level: level))
            }
            if !store.failingChecks.isEmpty {
                Button("Fix settings") { store.screen = .protection }
                    .buttonStyle(HeroButtonStyle(level: level, outline: !store.activeAlerts.isEmpty))
            }
            if store.activeAlerts.isEmpty && store.failingChecks.isEmpty {
                Button("Open full report") { store.open(store.status!.report) }
                    .buttonStyle(HeroButtonStyle(level: level, outline: true))
            }
        }
    }
}

// MARK: - Field Ops overview

/// "■ STATUS: ATTENTION", the headline and actions on the left; score and a 20-cell bar on the right.
struct OpsStatusBlock: View {
    @Environment(AppStore.self) private var store

    private var word: String {
        switch store.level {
        case .secure: "CLEAR"
        case .watch: "ATTENTION"
        case .danger: "THREAT"
        }
    }

    var body: some View {
        let level = store.level
        let filled = Int((Double(store.score) / 5).rounded())
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 7) {
                    Rectangle().fill(level.hero).frame(width: 8, height: 8)
                    Text("STATUS: \(word)").font(.ui(12.5, 700)).tracking(2).foregroundStyle(level.hero)
                }
                Text(store.headline.uppercased())
                    .font(.display(30, 700))
                    .tracking(-0.3)
                    .lineSpacing(3)
                    .foregroundStyle(Theme.text)
                    .fixedSize(horizontal: false, vertical: true)
                Text(store.heroMessage)
                    .font(.ui(13.5))
                    .lineSpacing(5)
                    .foregroundStyle(Theme.text2)
                    .fixedSize(horizontal: false, vertical: true)
                HeroActions(level: level).padding(.top, 6)
            }
            .padding(EdgeInsets(top: 22, leading: 24, bottom: 22, trailing: 24))
            .frame(maxWidth: .infinity, alignment: .leading)

            Rectangle().fill(Theme.line).frame(width: 1)

            VStack(alignment: .leading, spacing: 14) {
                Text("SECURITY SCORE").font(.ui(12.5)).tracking(2).foregroundStyle(Theme.text3)
                HStack(alignment: .lastTextBaseline, spacing: 6) {
                    Text(String(format: "%03d", store.score))
                        .font(.figure(89, 800)).tracking(-3)
                        .foregroundStyle(level.hero)
                        .contentTransition(.numericText())
                    Text("/100").font(.ui(15)).foregroundStyle(Theme.text3)
                }
                HStack(spacing: 3) {
                    ForEach(0..<20, id: \.self) { i in
                        Rectangle().fill(i < filled ? level.hero : Theme.line).frame(height: 14)
                    }
                }
            }
            .padding(EdgeInsets(top: 22, leading: 24, bottom: 22, trailing: 24))
            .frame(width: 330, alignment: .leading)
        }
        .skinOutline()
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// Four figures in one bordered strip.
struct OpsStatStrip: View {
    @Environment(AppStore.self) private var store

    private func cell(_ label: String, _ value: String, _ note: String?, _ noteColor: Color,
                      _ target: Screen) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.ui(12)).tracking(1.5).foregroundStyle(Theme.text3)
            HStack(alignment: .lastTextBaseline, spacing: 8) {
                Text(value).font(.figure(36, 700)).foregroundStyle(Theme.text).lineLimit(1)
                if let note { Text(note).font(.ui(12.5)).foregroundStyle(noteColor).lineLimit(1) }
            }
        }
        .padding(EdgeInsets(top: 14, leading: 18, bottom: 14, trailing: 14))
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .onTapGesture { store.screen = target }
    }

    var body: some View {
        let s = store.status!
        let off = store.failingChecks.count
        let on = store.checks.count - off
        let top = store.activeAlerts.first
        HStack(spacing: 0) {
            cell("THREATS", String(format: "%02d", store.activeAlerts.count),
                 top.map { String($0.severity.label.prefix(3)).uppercased() }, top?.severity.color ?? Theme.text3, .threats)
            Rectangle().fill(Theme.line).frame(width: 1)
            cell("PROTECTIONS", "\(on)/\(store.checks.count)", off > 0 ? "-\(off)" : nil, Theme.amber, .protection)
            Rectangle().fill(Theme.line).frame(width: 1)
            cell("APPS ONLINE", "\(s.connections.count)",
                 "\(s.connections.reduce(0) { $0 + $1.remotes.count }) CONN", Theme.text3, .network)
            Rectangle().fill(Theme.line).frame(width: 1)
            cell("PORTS", "\(s.listening.count)", "\(s.listening.filter(\.exposed).count) EXPOSED", Theme.text3, .network)
        }
        .skinOutline()
    }
}

/// Scans and findings in a `tail -f` style: time, level, message.
struct OpsEventLog: View {
    @Environment(AppStore.self) private var store

    private func levelText(_ l: Severity?) -> (String, Color) {
        switch l {
        case .high?: ("HIGH", Theme.red)
        case .medium?: ("MED", Theme.amber)
        case .low?: ("LOW", Theme.blue)
        default: ("INFO", Theme.text3)
        }
    }

    var body: some View {
        Tile(padding: 16) {
            VStack(alignment: .leading, spacing: 8) {
                TileHeader("Event log") {
                    Text("TAIL -F").font(.ui(12)).tracking(1.5).foregroundStyle(Theme.text3)
                }
                ForEach(store.logLines.prefix(8)) { line in
                    let (text, color) = levelText(line.level)
                    HStack(alignment: .firstTextBaseline, spacing: 14) {
                        Text(Fmt.date(line.time).map { $0.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits)) } ?? "—")
                            .foregroundStyle(Theme.text3)
                        Text(text).foregroundStyle(color).frame(width: 40, alignment: .leading)
                        Text(line.message).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.tail)
                        Spacer(minLength: 0)
                    }
                    .font(.ui(13))
                }
            }
        }
    }
}

/// Every protection and whether it is on.
struct OpsProtectionMatrix: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let checks = store.checks.sorted { ($0.failed ? 0 : 1) < ($1.failed ? 0 : 1) }
        Tile(padding: 16) {
            VStack(alignment: .leading, spacing: 4) {
                TileHeader("Protection matrix") {
                    Text("\(store.checks.count - store.failingChecks.count)/\(store.checks.count)")
                        .font(.ui(12)).tracking(1.5).foregroundStyle(Theme.text3)
                }
                .padding(.bottom, 4)
                ForEach(checks.prefix(8)) { c in
                    HStack {
                        Text(c.name).foregroundStyle(Theme.text).lineLimit(1)
                        Spacer(minLength: 8)
                        Text(c.passed ? "OK" : c.failed ? "RISK" : "?")
                            .font(.ui(13, 700))
                            .foregroundStyle(c.passed ? Theme.green : c.failed ? Theme.amber : Theme.text3)
                    }
                    .font(.ui(13))
                    .labelCase(tracking: 0.3)
                    .insetRow(padding: EdgeInsets(top: 6, leading: 0, bottom: 6, trailing: 0))
                    .onTapGesture { store.screen = .protection }
                }
            }
        }
    }
}
