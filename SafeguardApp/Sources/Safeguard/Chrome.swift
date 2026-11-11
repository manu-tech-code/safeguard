import AppKit
import SwiftUI

// MARK: - Shared navigation bits

/// What a navigation entry shows on its right: a count, how loud it is.
struct NavBadge {
    enum Kind { case alert, warn, quiet }
    let text: String
    let kind: Kind
}

extension AppStore {
    func navBadge(_ screen: Screen) -> NavBadge? {
        switch screen {
        case .threats: activeAlerts.isEmpty ? nil : NavBadge(text: "\(activeAlerts.count)", kind: .alert)
        case .protection: failingChecks.isEmpty ? nil : NavBadge(text: "\(failingChecks.count)", kind: .warn)
        case .network: status.map { NavBadge(text: "\($0.connections.count)", kind: .quiet) }
        default: nil
        }
    }

    var hostLine: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(status?.computer ?? "This Mac") · macOS \(v.majorVersion).\(v.minorVersion)"
    }
}

private func shortTitle(_ s: Screen) -> String { s == .startup ? "Startup" : s.title }

private struct NavButton<Label: View>: View {
    @Environment(AppStore.self) private var store
    let screen: Screen
    @ViewBuilder let label: (_ selected: Bool, _ hover: Bool) -> Label
    @State private var hover = false

    var body: some View {
        Button { store.screen = screen } label: {
            label(store.screen == screen, hover).contentShape(Rectangle()).focusEffectDisabled()
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .accessibilityLabel(screen.title)
    }
}

// MARK: - Sidebar (Graphite, Swiss, Hardware, Neo-Brutal)

struct SideNav: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        switch Theme.look {
        case .graphite: graphite
        case .swiss: swiss
        case .hardware: hardware
        default: brutal
        }
    }

    private var statusLine: String { store.autoScan ? "Auto-scan every \(store.intervalMinutes) min" : "Auto-scan off" }

    // MARK: A · Graphite

    private func graphiteItem(_ screen: Screen) -> some View {
        NavButton(screen: screen) { selected, hover in
            HStack(spacing: 10) {
                Image(systemName: screen.icon).font(.system(size: 13.5))
                    .foregroundStyle(selected ? Theme.accent : Theme.text2).frame(width: 16)
                Text(shortTitle(screen)).font(.ui(13.5, selected ? 500 : 400))
                    .foregroundStyle(selected ? Theme.text : Theme.text2)
                Spacer(minLength: 4)
                if let b = store.navBadge(screen) {
                    switch b.kind {
                    case .alert:
                        Text(b.text).font(.mono(11.5)).foregroundStyle(Theme.bg)
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(CapShape(radius: 5).fill(Theme.amber))
                    case .warn: Text(b.text).font(.mono(11.5)).foregroundStyle(Theme.amber)
                    case .quiet: Text(b.text).font(.mono(11.5)).foregroundStyle(Theme.text3)
                    }
                }
            }
            .padding(.vertical, 8).padding(.horizontal, 10)
            .background(CapShape(radius: 8).fill(selected ? Theme.inset : hover ? Theme.inset.opacity(0.5) : .clear))
            .overlay(alignment: .leading) {
                if selected {
                    Rectangle().fill(Theme.accent).frame(width: 3, height: 16).offset(x: -14)
                }
            }
        }
    }

    private var graphite: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 10) {
                BrandMark(size: 28)
                Text("Safeguard").font(.display(16, 700)).foregroundStyle(Theme.text)
            }
            .padding(.horizontal, 10).padding(.bottom, 24)
            Text("Monitor").font(.ui(11.5)).foregroundStyle(Theme.text3).padding(.horizontal, 10).padding(.bottom, 6)
            ForEach([Screen.overview, .threats, .protection, .network, .browser, .startup]) { graphiteItem($0) }
            Text("Tools").font(.ui(11.5)).foregroundStyle(Theme.text3)
                .padding(.horizontal, 10).padding(.top, 20).padding(.bottom, 6)
            graphiteItem(.advisor)
            graphiteItem(.links)
            graphiteItem(.activity)
            Spacer()
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Dot(color: store.level == .secure ? Theme.green : store.level.hero, size: 8)
                    Text(store.level.title).font(.ui(13, 500)).foregroundStyle(Theme.text)
                }
                Text(statusLine).font(.ui(12)).foregroundStyle(Theme.text3)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(PanelSurface(radius: 18, fill: .clear))
            .padding(.horizontal, 4).padding(.bottom, 10)
            graphiteItem(.settings)
        }
        .padding(.top, 44).padding(.horizontal, 14).padding(.bottom, 20)
        .frame(width: 232)
        .overlay(alignment: .trailing) { Rectangle().fill(Theme.line).frame(width: 1) }
    }

    // MARK: E · Swiss

    private func swissItem(_ screen: Screen) -> some View {
        let n = (Screen.allCases.firstIndex(of: screen) ?? 0) + 1
        return NavButton(screen: screen) { selected, _ in
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(String(format: "%02d", n)).font(.ui(11, 500))
                    .foregroundStyle(selected ? Theme.accent : Theme.text3).frame(width: 18, alignment: .leading)
                Text(shortTitle(screen)).font(.ui(15, selected ? 800 : 500))
                    .foregroundStyle(selected ? Theme.text : Theme.text2)
                Spacer(minLength: 4)
                if let b = store.navBadge(screen) {
                    Text(b.text).font(.ui(15, 800)).foregroundStyle(b.kind == .quiet ? Theme.text3 : Theme.accent)
                }
            }
            .padding(.vertical, 5)
        }
    }

    private var swiss: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Safe—\nguard.").font(.display(22, 800)).foregroundStyle(Theme.text).lineSpacing(-2).padding(.bottom, 4)
            Text("Personal security, v1.0").font(.ui(12)).foregroundStyle(Theme.text3).padding(.bottom, 30)
            ForEach(Screen.allCases.filter { $0 != .settings }) { swissItem($0) }
            Spacer()
            VStack(alignment: .leading, spacing: 3) {
                Text(store.status?.computer ?? "This Mac").font(.ui(12, 600)).foregroundStyle(Theme.text).lineLimit(1)
                Text(store.hostLine.components(separatedBy: " · ").last ?? "").font(.ui(12)).foregroundStyle(Theme.text3)
                Text("Scanned \(store.lastScanDate.map(Fmt.time) ?? "—")").font(.ui(12)).foregroundStyle(Theme.text3)
            }
            .padding(.top, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
            swissItem(.settings).padding(.top, 8)
        }
        .padding(.top, 44).padding(.horizontal, 26).padding(.bottom, 22)
        .frame(width: 220)
        .overlay(alignment: .trailing) { Rectangle().fill(Theme.text).frame(width: 3) }
    }

    // MARK: F · Hardware

    private func keycap(_ screen: Screen) -> some View {
        NavButton(screen: screen) { selected, hover in
            let alertDot = (screen == .threats && !store.activeAlerts.isEmpty) || (screen == .protection && !store.failingChecks.isEmpty)
            let fill = selected ? Color(hex: 0xE7E5DE) : hover ? Theme.insetHover : Theme.inset
            let lip = selected ? Color(hex: 0xA9A79F) : Color(hex: 0x141413)
            HStack(spacing: 10) {
                Dot(color: selected ? Theme.accent : alertDot ? Theme.amber : Theme.dim, size: 6)
                Text(shortTitle(screen)).font(.ui(13, selected ? 600 : 400))
                    .foregroundStyle(selected ? Color(hex: 0x1A1A18) : Theme.text)
                Spacer(minLength: 4)
                if let b = store.navBadge(screen) {
                    Text(b.text).font(.mono(11.5, .medium))
                        .foregroundStyle(selected ? Color(hex: 0x1A1A18) : b.kind == .quiet ? Theme.text3 : Theme.amber)
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 10).padding(.bottom, 3)
            .background {
                ZStack(alignment: .top) {
                    CapShape(radius: 8).fill(lip)
                    CapShape(radius: 8).fill(fill).padding(.bottom, 3)
                }
            }
        }
    }

    private func led(_ label: String, on: Bool) -> some View {
        HStack(spacing: 6) {
            Dot(color: on ? Theme.green : Theme.dim, size: 6)
            Text(label).font(.mono(10.5)).foregroundStyle(Theme.text3)
        }
    }

    private var hardware: some View {
        VStack(spacing: 6) {
            HStack {
                Text("SAFEGUARD").font(.mono(14, .semibold)).tracking(3).foregroundStyle(Theme.text)
                Spacer()
                Text("SG-1").font(.mono(10.5)).foregroundStyle(Theme.text3)
            }
            .padding(.horizontal, 6).padding(.bottom, 12)
            ForEach([Screen.overview, .threats, .protection, .network, .browser, .startup]) { keycap($0) }
            Rectangle().fill(Color(hex: 0x33332E)).frame(height: 1).padding(.horizontal, 4).padding(.vertical, 6)
            keycap(.advisor)
            keycap(.links)
            keycap(.activity)
            Spacer()
            LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)], spacing: 6) {
                led("ENGINE", on: store.status != nil && store.errorMessage == nil)
                led(store.autoScan ? "AUTO \(store.intervalMinutes)M" : "AUTO OFF", on: store.autoScan)
                led("NOTIFY", on: store.notificationsOn)
                led("BG SCAN", on: store.status?.scheduleInstalled == true)
            }
            .padding(.horizontal, 2).padding(.bottom, 10)
            keycap(.settings)
        }
        .padding(.top, 50).padding(.horizontal, 14).padding(.bottom, 14)
        .frame(width: 226)
        // Start the card below the traffic lights instead of under them.
        .background(PanelSurface(radius: 22, fill: Theme.tile).padding(.top, 34))
    }

    // MARK: G · Neo-Brutal

    private func brutalItem(_ screen: Screen) -> some View {
        NavButton(screen: screen) { selected, hover in
            HStack(spacing: 10) {
                Text(shortTitle(screen)).font(.ui(14, selected ? 600 : 500))
                    .foregroundStyle(selected ? Color.white : Color(hex: 0x111111))
                Spacer(minLength: 4)
                if let b = store.navBadge(screen) {
                    switch b.kind {
                    case .quiet: Text(b.text).font(.mono(12)).foregroundStyle(selected ? .white : Color(hex: 0x111111))
                    default:
                        Text(b.text).font(.mono(12, .bold)).foregroundStyle(Color(hex: 0x111111))
                            .padding(.horizontal, 6).padding(.vertical, 0.5)
                            .background(CapShape(radius: 6).fill(b.kind == .alert ? Color(hex: 0xFF5A4E) : Theme.warnFill))
                            .overlay(CapShape(radius: 6).strokeBorder(Color(hex: 0x111111), lineWidth: 2))
                    }
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(CapShape(radius: 10).fill(selected ? Color(hex: 0x111111) : hover ? Theme.insetHover : .clear))
        }
    }

    private var brutal: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                BrandMark(size: 30)
                Text("Safeguard").font(.display(18, 700)).foregroundStyle(Theme.text)
            }
            .padding(.horizontal, 6).padding(.bottom, 14)
            ForEach(Screen.allCases.filter { $0 != .settings }) { brutalItem($0) }
            Spacer()
            VStack(alignment: .leading, spacing: 2) {
                Text(store.level.title).font(.ui(13, 700)).foregroundStyle(Color(hex: 0x111111))
                Text("Scanned \(Fmt.relative(store.lastScanDate))").font(.ui(12)).foregroundStyle(Color(hex: 0x111111))
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(CapShape(radius: 10).fill(store.level == .secure ? Color(hex: 0x34C77B) : store.level == .danger ? Color(hex: 0xFF5A4E) : Theme.warnFill))
            .overlay(CapShape(radius: 10).strokeBorder(Color(hex: 0x111111), lineWidth: 2))
            brutalItem(.settings)
        }
        .padding(.top, 50).padding(.horizontal, 12).padding(.bottom, 14)
        .frame(width: 222)
        // Start the card below the traffic lights instead of under them.
        .background(PanelSurface(radius: 22, fill: Theme.tile).padding(.top, 34))
    }
}

// MARK: - Top bar (Dot Matrix)

struct TopNav: View {
    @Environment(AppStore.self) private var store

    private func pill(_ screen: Screen) -> some View {
        NavButton(screen: screen) { selected, hover in
            HStack(spacing: 6) {
                Text(shortTitle(screen))
                if screen == .threats, !store.activeAlerts.isEmpty { Text("●").foregroundStyle(Theme.red) }
            }
            .font(.ui(13, selected ? 500 : 400))
            .foregroundStyle(selected ? Color.black : Theme.text)
            .padding(.horizontal, 16).padding(.vertical, 7)
            .background(PillShape().fill(selected ? Color.white : hover ? Theme.inset : .clear))
            .overlay(PillShape().strokeBorder(selected ? Color.white : Theme.line, lineWidth: 1))
        }
    }

    var body: some View {
        HStack(spacing: 16) {
            HStack(spacing: 10) {
                DotLogo()
                Text("SAFEGUARD").font(Typeface.font(.doto, 22, 900)).tracking(1).foregroundStyle(Theme.text).fixedSize()
            }
            Spacer(minLength: 8)
            HStack(spacing: 5) {
                ForEach(Screen.allCases.filter { $0 != .settings }) { pill($0) }
            }
            Spacer(minLength: 8)
            NavButton(screen: .settings) { selected, hover in
                Image(systemName: "slider.horizontal.3").font(.system(size: 13))
                    .foregroundStyle(selected ? Color.black : Theme.text)
                    .frame(width: 36, height: 36)
                    .background(RoundShape().fill(selected ? Color.white : hover ? Theme.inset : .clear))
                    .overlay(RoundShape().strokeBorder(selected ? Color.white : Theme.line, lineWidth: 1))
            }
        }
        .padding(.leading, 84).padding(.trailing, 40).padding(.top, 14).padding(.bottom, 10)
    }
}

/// The Dot Matrix mark: nine white dots and five red ones.
struct DotLogo: View {
    var body: some View {
        Canvas { ctx, _ in
            let white: [(CGFloat, CGFloat)] = [(3, 3), (7.5, 3), (12.5, 3), (17, 3), (3, 8), (7.5, 8), (3, 13), (7.5, 13), (7.5, 18)]
            let red: [(CGFloat, CGFloat)] = [(12.5, 8), (17, 8), (12.5, 13), (17, 13), (12.5, 18)]
            for (pts, color) in [(white, Color.white), (red, Color(hex: 0xFF3B30))] {
                for (x, y) in pts {
                    ctx.fill(Path(ellipseIn: CGRect(x: x - 1.6, y: y - 1.6, width: 3.2, height: 3.2)), with: .color(color))
                }
            }
        }
        .frame(width: 20, height: 22)
    }
}

// MARK: - Field Ops chrome

/// Top status line: host, OS, baseline, last scan, and the scan button.
struct OpsHeader: View {
    @Environment(AppStore.self) private var store

    private var host: String {
        (store.status?.computer ?? "—").uppercased()
            .replacingOccurrences(of: "’", with: "").replacingOccurrences(of: "'", with: "")
            .replacingOccurrences(of: " ", with: "-")
    }

    private var os: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "MACOS \(v.majorVersion).\(v.minorVersion)"
    }

    private var baseline: String {
        Fmt.date(store.status?.baseline.taken).map { $0.formatted(.dateTime.day(.twoDigits).month(.twoDigits)) + " " + $0.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits)) } ?? "—"
    }

    private func field(_ label: String, _ value: String) -> some View {
        HStack(spacing: 6) {
            Text(label).foregroundStyle(Theme.text3)
            Text(value).foregroundStyle(Theme.text)
        }
        .font(.ui(13))
        .lineLimit(1)
    }

    var body: some View {
        HStack(spacing: 24) {
            Text("SAFEGUARD").font(.ui(13.5, 800)).tracking(2).foregroundStyle(Theme.accent).fixedSize()
            field("HOST", host).layoutPriority(-1)
            field("OS", os).fixedSize()
            field("BASELINE", baseline).fixedSize()
            Spacer(minLength: 8)
            TimelineView(.periodic(from: .now, by: 1)) { _ in
                field("LAST SCAN", store.scanning ? "SCANNING…"
                      : store.lastScanDate.map { $0.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits)) } ?? "—")
            }
            .fixedSize()
            Button {
                Task { await store.scan() }
            } label: {
                HStack(spacing: 7) {
                    if store.scanning { Spinner(color: Theme.accentInk, size: 10) } else { Text("⏎") }
                    Text(store.scanning ? "Scanning" : "Scan now")
                }
            }
            .buttonStyle(LightButtonStyle(compact: true))
            .disabled(store.scanning)
        }
        .padding(.leading, 84)
        .padding(.trailing, 20)
        .frame(height: 44)
        .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
    }
}

/// Left navigation: F-key labels, counts, and a status block at the bottom.
struct OpsNav: View {
    @Environment(AppStore.self) private var store

    private func shortTitle(_ s: Screen) -> String { s == .startup ? "Startup" : s.title }

    private func item(_ screen: Screen, key: Int, trailing: String? = nil, hot: Bool = false) -> some View {
        OpsNavItem(screen: screen, fkey: key, title: shortTitle(screen), trailing: trailing, hot: hot)
    }

    private func leader(_ label: String, _ value: String) -> some View {
        HStack(spacing: 6) {
            Text(label)
            DotLeader().frame(maxWidth: .infinity)
            Text(value)
        }
        .font(.ui(12.5))
        .foregroundStyle(Theme.text3)
        .lineLimit(1)
    }

    var body: some View {
        let alerts = store.activeAlerts.count
        let off = store.failingChecks.count
        VStack(spacing: 0) {
            item(.overview, key: 1)
            item(.threats, key: 2, trailing: alerts > 0 ? "[\(alerts)]" : nil, hot: true)
            item(.protection, key: 3, trailing: off > 0 ? "[\(off)]" : nil, hot: true)
            item(.network, key: 4, trailing: store.status.map { "\($0.connections.count)" })
            item(.browser, key: 5)
            item(.startup, key: 6)
            Rectangle().fill(Theme.line).frame(height: 1).padding(.horizontal, 20).padding(.vertical, 14)
            item(.links, key: 7)
            item(.activity, key: 8)
            item(.advisor, key: 9)
            Spacer()
            VStack(alignment: .leading, spacing: 6) {
                leader("AUTO-SCAN", store.autoScan ? "\(store.intervalMinutes)M" : "OFF")
                leader("ENGINE", store.status != nil && store.errorMessage == nil ? "OK" : "ERR")
                leader("NOTIFY", store.notificationsOn ? "ON" : "OFF")
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 14)
            item(.settings, key: 10)
                .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
        }
        .padding(.top, 18)
        .frame(width: 200)
        .overlay(alignment: .trailing) { Rectangle().fill(Theme.line).frame(width: 1) }
    }
}

struct OpsNavItem: View {
    @Environment(AppStore.self) private var store
    let screen: Screen
    let fkey: Int
    let title: String
    var trailing: String?
    var hot = false
    @State private var hover = false

    var body: some View {
        let selected = store.screen == screen
        Button {
            store.screen = screen
        } label: {
            HStack(spacing: 12) {
                Text("F\(fkey)").foregroundStyle(selected ? Theme.accentInk.opacity(0.7) : Theme.text3)
                Text(title).labelCase(tracking: 0.5).foregroundStyle(selected ? Theme.accentInk : Theme.text)
                Spacer(minLength: 4)
                if let trailing {
                    Text(trailing).foregroundStyle(selected ? Theme.accentInk : hot ? Theme.accent : Theme.text3)
                }
            }
            .font(.ui(13.5, selected ? 700 : 400))
            .lineLimit(1)
            .padding(.horizontal, 20)
            .padding(.vertical, 9)
            .background(selected ? Theme.accent : hover ? Theme.inset : .clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .keyboardShortcut(KeyEquivalent(Character(UnicodeScalar(UInt32(NSF1FunctionKey) + UInt32(fkey - 1))!)), modifiers: [])
        .help("\(screen.title) (F\(fkey))")
    }
}

/// A row of dots between a label and its value.
struct DotLeader: View {
    var body: some View {
        GeometryReader { g in
            Path { p in
                p.move(to: CGPoint(x: 0, y: g.size.height - 3))
                p.addLine(to: CGPoint(x: g.size.width, y: g.size.height - 3))
            }
            .stroke(Theme.dim, style: StrokeStyle(lineWidth: 1.6, lineCap: .round, dash: [0.1, 4.5]))
        }
        .frame(height: 12)
    }
}

