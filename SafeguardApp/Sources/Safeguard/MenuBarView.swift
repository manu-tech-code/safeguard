import AppKit
import SwiftUI

/// The menu bar icon: a shield that gains an exclamation mark when something needs attention.
struct MenuBarLabel: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let symbol = store.status == nil ? "shield"
            : store.activeAlerts.isEmpty && store.failingChecks.isEmpty ? "checkmark.shield.fill"
            : "exclamationmark.shield.fill"
        Image(systemName: symbol)
            .accessibilityLabel("Safeguard: \(store.status == nil ? "starting" : store.level.title)")
    }
}

/// The panel that drops down from the menu bar icon. A small Bento board: status hero, counts,
/// top findings, a link check and the main actions.
struct MenuBarPanel: View {
    @Environment(AppStore.self) private var store
    @Environment(\.openWindow) private var openWindow
    @State private var link = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if store.status != nil {
                hero
                HStack(spacing: 10) {
                    countTile("Threats", store.activeAlerts.count, color: store.activeAlerts.isEmpty ? Theme.green : store.level.color,
                              screen: .threats)
                    countTile("Protections off", store.failingChecks.count,
                              color: store.failingChecks.isEmpty ? Theme.green : Theme.amber, screen: .protection)
                }
                if !store.activeAlerts.isEmpty { findings }
                linkCheck
            } else {
                HStack(spacing: 8) {
                    Spinner(size: 12)
                    Text(store.errorMessage ?? "Running the first scan…").font(.ui(13)).foregroundStyle(Theme.text2)
                }
                .insetRow()
            }
            footer
        }
        .padding(12)
        .frame(width: 360)
        .background(Theme.bg)
        .preferredColorScheme(Theme.skin.dark ? .dark : .light)
        .onAppear { store.openMainWindowAction = { openWindow(id: "main") } }
    }

    private var header: some View {
        HStack(spacing: 10) {
            BrandMark(size: 26)
            VStack(alignment: .leading, spacing: 1) {
                Text("Safeguard").font(.display(16)).foregroundStyle(Theme.text)
                TimelineView(.periodic(from: .now, by: 30)) { _ in
                    Text(store.scanning ? "Scanning…" : "Scanned \(Fmt.relative(store.lastScanDate))")
                        .font(.ui(11.5)).foregroundStyle(Theme.text3)
                }
            }
            Spacer()
            Button { show(.settings) } label: { Image(systemName: "gearshape") }
                .buttonStyle(RoundIconButtonStyle())
                .help("Settings")
        }
        .padding(.horizontal, 4)
        .padding(.top, 2)
    }

    private var hero: some View {
        let level = store.level
        return Button { show(.overview) } label: {
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 8) {
                    HeroBadge(text: level.badge, color: level.hero, ink: level.heroInk, size: 11.5)
                    Text(store.headline)
                        .font(.display(18))
                        .foregroundStyle(level.heroInk)
                        .multilineTextAlignment(.leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 4)
                Text("\(store.score)")
                    .font(.figure(54, 800))
                    .foregroundStyle(Theme.skin.heroFilled ? level.heroInk : level.hero)
                    .monospacedDigit()
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .heroSurface(level.hero)
            .contentShape(RoundedRectangle(cornerRadius: Theme.corner(18), style: .continuous))
        }
        .buttonStyle(.plain)
        .help("Open the overview")
    }

    private func countTile(_ label: String, _ value: Int, color: Color, screen: Screen) -> some View {
        Button { show(screen) } label: {
            VStack(alignment: .leading, spacing: 4) {
                Text(label).font(.ui(12, 500)).foregroundStyle(Theme.text2)
                HStack(spacing: 8) {
                    Text("\(value)").font(.figure(26)).foregroundStyle(Theme.text)
                    Dot(color: color, size: 8)
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(PanelSurface(radius: 16, fill: Theme.tile))
            .contentShape(RoundedRectangle(cornerRadius: Theme.corner(16), style: .continuous))
        }
        .buttonStyle(.plain)
    }

    private var findings: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(store.activeAlerts.prefix(3)) { alert in
                Button {
                    store.selectedAlertID = alert.id
                    show(.threats)
                } label: {
                    HStack(spacing: 10) {
                        Dot(color: alert.severity.color, size: 8)
                        Text(alert.title).font(.ui(12.5, 500)).foregroundStyle(Theme.text).lineLimit(1)
                        Spacer(minLength: 6)
                        Text(alert.severity.label).font(.ui(11.5, 600)).foregroundStyle(alert.severity.color).labelCase()
                    }
                    .insetRow(padding: EdgeInsets(top: 9, leading: 12, bottom: 9, trailing: 12))
                }
                .buttonStyle(.plain)
            }
            if store.activeAlerts.count > 3 {
                Button("See all \(store.activeAlerts.count) threats") { show(.threats) }
                    .buttonStyle(TextLinkStyle())
                    .padding(.leading, 4)
            }
        }
        .padding(10)
        .background(PanelSurface(radius: 16, fill: Theme.tile))
    }

    private var linkCheck: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "link").font(.system(size: 12)).foregroundStyle(Theme.text3)
                TextField("", text: $link, prompt: Text("Paste a link to check").foregroundStyle(Theme.text3))
                    .textFieldStyle(.plain)
                    .font(.ui(12.5))
                    .foregroundStyle(Theme.text)
                    .onSubmit(check)
                if store.checkingURL {
                    Spinner(size: 11)
                } else if !link.isEmpty {
                    Button("Check", action: check).buttonStyle(CoralButtonStyle(compact: true))
                }
            }
            .padding(.leading, 14).padding(.trailing, 5).padding(.vertical, 5)
            .frame(minHeight: 36)
            .background(PillShape().fill(Theme.inset))

            if let last = store.urlChecks.first, Date.now.timeIntervalSince(last.checkedAt ?? .distantPast) < 600 {
                let look = verdictLook(last.verdict)
                Button { show(.links) } label: {
                    HStack(spacing: 10) {
                        Text(look.short)
                            .font(.tag(11.5, 600)).foregroundStyle(Theme.skin.heroFilled ? look.ink : look.fill)
                            .labelCase()
                            .padding(.horizontal, 9).padding(.vertical, 3)
                            .background(PillShape().fill(Theme.skin.heroFilled ? look.fill : .clear))
                            .overlay { if !Theme.skin.heroFilled { PillShape().strokeBorder(look.fill, lineWidth: 1) } }
                        Text(last.url).font(.mono(11)).foregroundStyle(Theme.text2)
                            .lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 4)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(10)
        .background(PanelSurface(radius: 16, fill: Theme.tile))
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Button {
                Task { await store.scan() }
            } label: {
                HStack(spacing: 6) {
                    if store.scanning { Spinner(color: Theme.bg, size: 10) }
                    Text(store.scanning ? "Scanning" : "Scan now")
                }
            }
            .buttonStyle(LightButtonStyle(compact: true))
            .disabled(store.scanning)
            Button("Open Safeguard") { show(store.screen) }.buttonStyle(GhostButtonStyle(compact: true))
            Spacer()
            Button("Quit") { NSApp.terminate(nil) }.buttonStyle(TextLinkStyle(color: Theme.text3))
        }
        .padding(.horizontal, 4)
        .padding(.top, 2)
    }

    private func check() {
        let value = link
        Task {
            await store.checkURL(value)
            link = ""
        }
    }

    private func show(_ screen: Screen) {
        store.screen = screen
        store.showMainWindow()
    }
}
