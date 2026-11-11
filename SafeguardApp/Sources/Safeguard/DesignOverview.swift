import SwiftUI

// The Overview for Graphite, Dot Matrix, Swiss, Hardware and Neo-Brutal. They share a skeleton
// (hero, four figures, activity next to protections, then the usual tiles) and differ in how each
// piece is drawn.

struct DesignOverview: View {
    var body: some View {
        let gap = Theme.skin.gap
        VStack(spacing: gap) {
            DesignHero()
            DesignStats()
            HStack(alignment: .top, spacing: gap) {
                DesignActivity().frame(maxWidth: .infinity)
                DesignProtections().frame(maxWidth: .infinity)
            }
            .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: gap) {
                FixTheseTile()
                QuickLinkTile()
            }
            .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: gap) {
                RecentFindingsTile()
                WatchZonesTile()
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Hero

struct DesignHero: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let level = store.level
        switch Theme.look {
        case .graphite: graphite(level)
        case .dotmatrix: dotmatrix(level)
        case .swiss: swiss(level)
        case .hardware: hardware(level)
        default: brutal(level)
        }
    }

    private func headline(_ size: CGFloat, weight: CGFloat = 700) -> some View {
        Text(store.headline).font(.display(size, weight)).foregroundStyle(Theme.text)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func message(_ size: CGFloat = 13.5) -> some View {
        Text(store.heroMessage).font(.ui(size)).foregroundStyle(Theme.text2).lineSpacing(3)
            .fixedSize(horizontal: false, vertical: true)
    }

    // A · a ring gauge in a quiet panel
    private func graphite(_ level: ThreatLevel) -> some View {
        Tile(padding: 24, hero: true) {
            HStack(spacing: 32) {
                ZStack {
                    Circle().stroke(Theme.line, lineWidth: 10)
                    Circle().trim(from: 0, to: CGFloat(store.score) / 100)
                        .stroke(level.hero, style: StrokeStyle(lineWidth: 10, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                    VStack(spacing: 4) {
                        Text("\(store.score)").font(.figure(44, 700)).tracking(-1.5).foregroundStyle(Theme.text)
                            .contentTransition(.numericText())
                        Text("of 100").font(.ui(11.5)).foregroundStyle(Theme.text3)
                    }
                }
                .frame(width: 148, height: 148)
                VStack(alignment: .leading, spacing: 10) {
                    HeroBadge(text: level.badge, color: level.hero, size: 12.5)
                    headline(24)
                    message().frame(maxWidth: 560, alignment: .leading)
                    HeroActions(level: level).padding(.top, 4)
                }
                Spacer(minLength: 0)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    // C · a giant dotted score on black, split from the rest by a dotted rule
    private func dotmatrix(_ level: ThreatLevel) -> some View {
        VStack(spacing: 0) {
            HStack(alignment: .bottom, spacing: 40) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("SECURITY SCORE").font(.label(12)).tracking(1).foregroundStyle(Theme.text3)
                    HStack(alignment: .top, spacing: 6) {
                        Text("\(store.score)").font(.figure(150, 900)).foregroundStyle(Theme.text)
                            .lineLimit(1).fixedSize()
                            .contentTransition(.numericText())
                        Text("/100").font(.label(13)).foregroundStyle(Theme.text3).padding(.top, 14)
                    }
                }
                VStack(alignment: .leading, spacing: 12) {
                    HeroBadge(text: level.badge, color: level.hero, size: 12)
                    headline(28, weight: 700)
                    message(14)
                    HeroActions(level: level).padding(.top, 2)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.bottom, 6)
            }
            .padding(.bottom, 24)
            RuleLine(style: .dotted, color: Theme.edge)
        }
    }

    // E · type only: an enormous score, a heavy headline, thick rule underneath
    private func swiss(_ level: ThreatLevel) -> some View {
        VStack(spacing: 0) {
            HStack(alignment: .bottom, spacing: 40) {
                VStack(alignment: .leading, spacing: 0) {
                    Text("Security score / 100").font(.ui(12, 600)).foregroundStyle(Theme.text3)
                    Text("\(store.score)").font(.figure(200, 800)).tracking(-12)
                        .foregroundStyle(Theme.text).lineLimit(1).fixedSize()
                        .padding(.leading, -8).padding(.top, -14).padding(.bottom, -10)
                        .contentTransition(.numericText())
                }
                VStack(alignment: .leading, spacing: 14) {
                    Text("\(level.badge).").font(.ui(13, 800)).foregroundStyle(level.hero)
                    ViewThatFits(in: .vertical) {
                        headline(36, weight: 700)
                        headline(28, weight: 700)
                        headline(22, weight: 700)
                    }
                    message(14).frame(maxWidth: 520, alignment: .leading)
                    HStack(spacing: 22) {
                        if !store.activeAlerts.isEmpty {
                            Button("Review finding →") {
                                store.selectedAlertID = store.activeAlerts.first?.id
                                store.screen = .threats
                            }
                            .buttonStyle(SwissLink(color: Theme.accent))
                        }
                        if !store.failingChecks.isEmpty {
                            Button("Fix settings →") { store.screen = .protection }.buttonStyle(SwissLink(color: Theme.text))
                        }
                        if store.activeAlerts.isEmpty && store.failingChecks.isEmpty {
                            Button("Open full report →") { store.open(store.status!.report) }
                                .buttonStyle(SwissLink(color: Theme.text))
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.bottom, 6)
            }
            .padding(.vertical, 20)
            Rectangle().fill(Theme.text).frame(height: 3)
        }
    }

    // F · an LCD readout next to the message, keycap buttons
    private func hardware(_ level: ThreatLevel) -> some View {
        let sage = Color(hex: 0xB7C0A1)
        let ink = Color(hex: 0x1C2216)
        let filled = Int((Double(store.score) / 5).rounded())
        return Tile(padding: 22, hero: true) {
            HStack(alignment: .center, spacing: 26) {
                ZStack {
                    CapShape(radius: 10).fill(Color(hex: 0x0B0B0A))
                    CapShape(radius: 6).fill(sage).padding(8)
                        .overlay {
                            VStack(alignment: .leading, spacing: 0) {
                                HStack {
                                    Text("SECURITY SCORE")
                                    Spacer()
                                    Text(level == .secure ? "OK" : level == .danger ? "ALERT" : "ATTN")
                                }
                                .font(.mono(11, .semibold))
                                Spacer(minLength: 4)
                                HStack(alignment: .firstTextBaseline, spacing: 6) {
                                    Text("\(store.score)").font(.mono(86, .semibold)).tracking(-6).lineLimit(1)
                                    Text("/100").font(.mono(14, .medium))
                                }
                                Spacer(minLength: 4)
                                HStack(spacing: 3) {
                                    ForEach(0..<20, id: \.self) { i in
                                        Rectangle().fill(i < filled ? ink : ink.opacity(0.18)).frame(height: 8)
                                    }
                                }
                            }
                            .foregroundStyle(ink)
                            .padding(.horizontal, 24).padding(.vertical, 20)
                        }
                }
                .frame(width: 300, height: 156)
                VStack(alignment: .leading, spacing: 12) {
                    HeroBadge(text: level.badge, color: level.hero, size: 11.5)
                    headline(26, weight: 700)
                    message(14)
                    HeroActions(level: level).padding(.top, 4)
                }
                Spacer(minLength: 0)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    // G · a yellow poster block and a white score card
    private func brutal(_ level: ThreatLevel) -> some View {
        let g = Theme.skin.gap
        return HStack(alignment: .top, spacing: g) {
            Tile(padding: 24, fill: level.hero, hero: true) {
                VStack(alignment: .leading, spacing: 12) {
                    HeroBadge(text: level.badge, color: level.hero, size: 12)
                    Text(store.headline).font(.display(32, 700)).foregroundStyle(level.heroInk)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(store.heroMessage).font(.ui(14.5)).foregroundStyle(level.heroInkSoft)
                        .fixedSize(horizontal: false, vertical: true)
                    HeroActions(level: level).padding(.top, 4)
                }
            }
            Tile(padding: 20) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Security score").font(.ui(13, 600)).foregroundStyle(Theme.text)
                    Text("\(store.score)").font(.figure(104, 700)).tracking(-6).lineLimit(1)
                        .foregroundStyle(Theme.text).contentTransition(.numericText())
                    GeometryReader { g in
                        ZStack(alignment: .leading) {
                            Capsule().fill(.white)
                            Capsule().fill(Color(hex: 0x34C77B))
                                .frame(width: max(14, g.size.width * CGFloat(store.score) / 100))
                        }
                        .overlay(Capsule().strokeBorder(Color(hex: 0x111111), lineWidth: 2))
                    }
                    .frame(height: 16)
                }
            }
            .frame(width: 250)
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// Swiss text link: bold, no chrome.
struct SwissLink: ButtonStyle {
    var color: Color
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ui(14, 800))
            .foregroundStyle(color.opacity(configuration.isPressed ? 0.7 : 1))
            .contentShape(Rectangle())
    }
}

// MARK: - Four figures

struct DesignStats: View {
    @Environment(AppStore.self) private var store

    private struct Cell {
        let label: String
        let value: String
        let note: String?
        let noteColor: Color
        let target: Screen
    }

    private var cells: [Cell] {
        let s = store.status!
        let off = store.failingChecks.count
        let top = store.activeAlerts.first
        return [
            Cell(label: "Active threats", value: "\(store.activeAlerts.count)",
                 note: top.map { $0.severity.label.lowercased() }, noteColor: top?.severity.color ?? Theme.text3, target: .threats),
            Cell(label: "Protections on", value: "\(store.checks.count - off)/\(store.checks.count)",
                 note: off > 0 ? "\(off) off" : nil, noteColor: Theme.amber, target: .protection),
            Cell(label: "Apps online", value: "\(s.connections.count)",
                 note: "\(s.connections.reduce(0) { $0 + $1.remotes.count }) connections", noteColor: Theme.text3, target: .network),
            Cell(label: "Open ports", value: "\(s.listening.count)",
                 note: "\(s.listening.filter(\.exposed).count) reachable", noteColor: Theme.text3, target: .network),
        ]
    }

    var body: some View {
        let gap = Theme.skin.gap
        let cells = cells
        switch Theme.look {
        case .swiss:
            HStack(spacing: 0) {
                ForEach(Array(cells.enumerated()), id: \.offset) { i, c in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(c.label).font(.ui(12)).foregroundStyle(Theme.text3)
                        Text(c.value).font(.figure(42, 800)).tracking(-2)
                            .foregroundStyle(i == 0 && !store.activeAlerts.isEmpty ? Theme.accent : Theme.text)
                            .lineLimit(1).minimumScaleFactor(0.6)
                    }
                    .padding(.vertical, 14).padding(.leading, i == 0 ? 0 : 20).padding(.trailing, 20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                    .onTapGesture { store.screen = c.target }
                    if i < cells.count - 1 { Rectangle().fill(Theme.line).frame(width: 1) }
                }
            }
            .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
        case .dotmatrix:
            HStack(spacing: gap) {
                ForEach(Array(cells.enumerated()), id: \.offset) { i, c in
                    let hot = i == 0 && !store.activeAlerts.isEmpty
                    Tile(padding: 16, fill: hot ? Theme.accent : Theme.tile) {
                        HStack(alignment: .bottom) {
                            Text(c.label).font(.ui(13, hot ? 500 : 400)).foregroundStyle(hot ? Color.black : Theme.text2)
                            Spacer(minLength: 6)
                            Text(c.value).font(.figure(44, 900)).foregroundStyle(hot ? Color.black : Theme.text)
                                .lineLimit(1).minimumScaleFactor(0.6)
                        }
                    }
                    .onTapGesture { store.screen = c.target }
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        case .brutal:
            HStack(spacing: gap) {
                ForEach(Array(cells.enumerated()), id: \.offset) { i, c in
                    let fill: Color = i == 0 && !store.activeAlerts.isEmpty ? Color(hex: 0xFF5A4E)
                        : i == 3 ? Color(hex: 0x8FD3FF) : .white
                    Tile(padding: 14, fill: fill) {
                        VStack(alignment: .leading, spacing: 0) {
                            Text(c.label).font(.ui(13, 600)).foregroundStyle(Theme.text)
                            Text(c.value).font(.figure(38, 700)).tracking(-1).foregroundStyle(Theme.text)
                                .lineLimit(1).minimumScaleFactor(0.6)
                        }
                    }
                    .onTapGesture { store.screen = c.target }
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        default:
            HStack(spacing: gap) {
                ForEach(Array(cells.enumerated()), id: \.offset) { _, c in
                    Tile(padding: 16) {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(c.label).font(.label(12.5, 400)).foregroundStyle(Theme.text3).labelCase(tracking: 1)
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(c.value).font(.figure(28, 700)).tracking(-0.8).foregroundStyle(Theme.text)
                                    .lineLimit(1).minimumScaleFactor(0.6)
                                if let note = c.note {
                                    Text(note).font(.ui(12.5)).foregroundStyle(c.noteColor).lineLimit(1)
                                }
                            }
                        }
                    }
                    .onTapGesture { store.screen = c.target }
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Activity and protections

struct DesignActivity: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let values = (store.status?.history ?? []).suffix(24).map(\.online)
        Tile(padding: 20) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Activity").font(.ui(14, 600)).foregroundStyle(Theme.text).labelCase(tracking: 1.5, control: true)
                    Spacer()
                    Text("Apps online per scan").font(.label(12)).foregroundStyle(Theme.text3).labelCase()
                }
                if values.count < 2 {
                    EmptyNote(symbol: "waveform.path.ecg", title: "Not enough scans yet",
                              message: "Safeguard will draw a chart here after a few scans.")
                } else if Theme.look == .dotmatrix {
                    dots(values)
                } else {
                    bars(values)
                }
            }
        }
    }

    private func bars(_ values: [Int]) -> some View {
        let peak = CGFloat(max(1, values.max() ?? 1))
        let look = Theme.look
        let spacing: CGFloat = look == .swiss ? 4 : 6
        return HStack(alignment: .bottom, spacing: spacing) {
            ForEach(Array(values.enumerated()), id: \.offset) { i, v in
                let last = i == values.count - 1
                let color: Color = {
                    switch look {
                    case .swiss: return last ? Theme.accent : Theme.text
                    case .brutal: return last ? Color(hex: 0xFF5A4E) : Theme.warnFill
                    case .hardware: return last ? Theme.accent : Color(hex: 0x4A4A44)
                    default: return last ? Theme.accent : Theme.sparkBase
                    }
                }()
                CapShape(radius: look == .swiss ? 0 : 3).fill(color)
                    .overlay {
                        if look == .brutal { CapShape(radius: 3).strokeBorder(Color(hex: 0x111111), lineWidth: 2) }
                    }
                    .frame(height: max(6, 118 * CGFloat(v) / peak))
            }
        }
        .frame(height: 124, alignment: .bottom)
        .padding(look == .hardware ? 14 : 0)
        .background { if look == .hardware { CapShape(radius: 8).fill(Theme.well) } }
        .overlay(alignment: .bottom) {
            if look == .swiss { Rectangle().fill(Theme.text).frame(height: 3).offset(y: 3) }
            if look == .brutal { Rectangle().fill(Color(hex: 0x111111)).frame(height: 2).offset(y: 2) }
        }
    }

    private func dots(_ values: [Int]) -> some View {
        let peak = CGFloat(max(1, values.max() ?? 1))
        return HStack(alignment: .bottom, spacing: 7) {
            ForEach(Array(values.enumerated()), id: \.offset) { i, v in
                let lit = Int((CGFloat(v) / peak * 8).rounded())
                VStack(spacing: 5) {
                    ForEach(0..<8, id: \.self) { r in
                        Circle()
                            .fill(8 - r <= lit ? (i == values.count - 1 ? Theme.red : Theme.text) : Color(hex: 0x262626))
                            .frame(width: 9, height: 9)
                    }
                }
                .frame(maxWidth: .infinity)
            }
        }
        .frame(height: 124, alignment: .bottom)
    }
}

struct DesignProtections: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let checks = store.checks.sorted { ($0.failed ? 0 : 1) < ($1.failed ? 0 : 1) }
        Tile(padding: 20) {
            VStack(alignment: .leading, spacing: 4) {
                TileHeader("Protection") {
                    Button("See all") { store.screen = .protection }.buttonStyle(TextLinkStyle())
                }
                .padding(.bottom, 4)
                ForEach(checks.prefix(6)) { c in
                    let color = c.passed ? (Theme.look == .dotmatrix ? Theme.text3 : Theme.green) : c.failed ? Theme.amber : Theme.text3
                    let state = c.passed ? "Safe" : c.failed ? "At risk" : "Unknown"
                    HStack(spacing: 10) {
                        if Theme.look == .graphite || Theme.look == .hardware { Dot(color: color, size: 8) }
                        Text(c.name).font(.ui(13, c.failed && Theme.look == .swiss ? 800 : 400))
                            .foregroundStyle(c.failed ? Theme.text : Theme.text2).lineLimit(1)
                        Spacer(minLength: 8)
                        if Theme.skin.pills == .sticker {
                            Pill(state, color: c.failed ? Theme.amber : c.passed ? Theme.green : Theme.text3)
                        } else {
                            Text(state).font(.tag(12, Theme.look == .swiss ? 800 : 500))
                                .foregroundStyle(Theme.look == .swiss && c.failed ? Theme.accent : color)
                                .labelCase()
                        }
                    }
                    .insetRow(padding: EdgeInsets(top: 7, leading: 0, bottom: 7, trailing: 0))
                    .onTapGesture { store.screen = .protection }
                }
            }
        }
    }
}
