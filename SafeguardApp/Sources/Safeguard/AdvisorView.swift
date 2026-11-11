import SwiftUI

/// A dedicated screen for the advisor: brief the whole scan, pick a finding, ask.
struct AdvisorView: View {
    @Environment(AppStore.self) private var store
    @State private var selectedID: String?

    private var alerts: [ThreatAlert] { store.activeAlerts }
    private var selected: ThreatAlert? { alerts.first { $0.id == selectedID } ?? alerts.first }
    private var enabled: Bool { store.advisor?.enabled == true }
    private var isLocal: Bool { store.advisor?.provider == "local" }
    private var needsKey: Bool { !isLocal && store.advisor?.keyPresent != true }

    var body: some View {
        ScreenScaffold(.advisor) {
            VStack(spacing: 12) {
                if enabled {
                    header
                    HStack(alignment: .top, spacing: 12) {
                        findings.frame(width: 420)
                        detail
                    }
                    digest
                } else {
                    setup
                }
            }
        }
    }

    // MARK: header

    private var header: some View {
        Tile(padding: 20) {
            HStack(spacing: 14) {
                Image(systemName: "sparkles")
                    .font(.system(size: 17))
                    .foregroundStyle(Theme.text)
                    .frame(width: 42, height: 42)
                    .background(RoundShape().fill(Theme.inset))
                VStack(alignment: .leading, spacing: 3) {
                    Text("Advisor").font(.display(20)).foregroundStyle(Theme.text)
                    Text("\(store.advisor?.provider ?? "") · \(store.advisor?.model ?? "") · "
                         + "\(store.advisor?.callsToday ?? 0)/\(store.advisor?.dailyCap ?? 40) requests today")
                        .font(.ui(12.5)).foregroundStyle(Theme.text3).lineLimit(1)
                }
                Spacer()
                if needsKey {
                    Pill("No API key yet")
                }
                if store.digestBusy { Spinner(color: Theme.text2, size: 10) }
                Button("Brief me") { Task { await store.askDigest() } }
                    .buttonStyle(LightButtonStyle(compact: true))
                    .disabled(store.digestBusy || needsKey)
                Button("Settings") { store.screen = .settings }
                    .buttonStyle(GhostButtonStyle(compact: true))
            }
        }
    }

    // MARK: findings list

    private var findings: some View {
        Tile(padding: 16) {
            VStack(alignment: .leading, spacing: 10) {
                TileHeader("Findings", caption: "Pick one, then ask about it")
                if alerts.isEmpty {
                    EmptyNote(symbol: "checkmark.shield", title: "Nothing to review",
                              message: "When something changes, it appears here and you can ask about it.")
                }
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(alerts.prefix(15)) { alert in
                            Button { selectedID = alert.id } label: {
                                row(alert, selected: alert.id == selected?.id)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .frame(maxHeight: 430)
                .scrollIndicators(.never)
            }
        }
    }

    private func row(_ alert: ThreatAlert, selected: Bool) -> some View {
        HStack(spacing: 10) {
            Dot(color: alert.severity.color, size: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(alert.title).font(.ui(13, selected ? 600 : 500))
                    .foregroundStyle(Theme.text).lineLimit(2)
                    .multilineTextAlignment(.leading)
                Text(alert.kindLabel).font(.ui(11.5)).foregroundStyle(Theme.text3)
            }
            Spacer(minLength: 4)
            if selected {
                Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Theme.text3)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background(CapShape(radius: 9).fill(selected ? Theme.inset : .clear))
        .contentShape(Rectangle())
    }

    // MARK: selected finding

    private var detail: some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 14) {
                if let alert = selected {
                    HStack(spacing: 8) {
                        Pill(alert.severity.label, color: alert.severity.color,
                             fill: alert.severity.color.opacity(0.14))
                        Text(alert.kindLabel).font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                        Spacer()
                    }
                    Text(alert.title).font(.display(24)).foregroundStyle(Theme.text)
                        .fixedSize(horizontal: false, vertical: true)
                    if let first = Fmt.date(alert.firstSeen) {
                        Text("First seen \(Fmt.dateTime(first))").font(.ui(12)).foregroundStyle(Theme.text3)
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Text("What Safeguard found").font(.ui(12, 500)).foregroundStyle(Theme.text3)
                        Text(alert.detail).font(.mono(11.5)).foregroundStyle(Theme.text)
                            .lineSpacing(2)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                            .background(RoundedRectangle(cornerRadius: Theme.corner(12), style: .continuous)
                                .fill(Theme.well))
                    }
                    Text(alert.appAdvice).font(.ui(13.5)).foregroundStyle(Theme.text)
                        .lineSpacing(2)
                        .fixedSize(horizontal: false, vertical: true)
                    Rectangle().fill(Theme.line).frame(height: 1).opacity(0.6)
                    AdvisorPanel(alert: alert)
                } else {
                    EmptyNote(symbol: "sparkles", title: "Ask about anything",
                              message: "Choose a finding on the left, or ask for a briefing below.")
                }
            }
        }
    }

    // MARK: digest

    private var digest: some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 12) {
                TileHeader("Brief me", caption: "A calm summary of the latest scan. Nothing is changed.") {
                    Button("Refresh") { Task { await store.askDigest() } }
                        .buttonStyle(TextLinkStyle(color: Theme.text3))
                        .disabled(store.digestBusy || needsKey)
                }
                if needsKey {
                    Text("Add an API key in Settings, or switch to a local model, to use the advisor.")
                        .font(.ui(13)).foregroundStyle(Theme.text2)
                } else if let d = store.advisorDigest {
                    if let summary = d.summary, !summary.isEmpty {
                        Text(summary).font(.ui(14)).foregroundStyle(Theme.text)
                            .lineSpacing(3)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let priorities = d.priorities, !priorities.isEmpty {
                        ForEach(Array(priorities.enumerated()), id: \.offset) { i, point in
                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                Text("\(i + 1)").font(.figure(15, 600)).foregroundStyle(Theme.text3)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(point.finding).font(.ui(13, 600)).foregroundStyle(Theme.text)
                                    if !point.next.isEmpty {
                                        Text(point.next).font(.ui(12.5)).foregroundStyle(Theme.text2)
                                    }
                                }
                            }
                            .insetRow(padding: EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                        }
                    }
                } else if store.digestBusy {
                    HStack(spacing: 10) {
                        Spinner(color: Theme.text2, size: 10)
                        Text("Reading the scan…").font(.ui(13)).foregroundStyle(Theme.text2)
                    }
                    .insetRow()
                } else {
                    HStack(spacing: 12) {
                        Button("Brief me") { Task { await store.askDigest() } }
                            .buttonStyle(LightButtonStyle(compact: true))
                        Text("Runs read-only checks, then summarises the scan.")
                            .font(.ui(12)).foregroundStyle(Theme.text3)
                    }
                    .insetRow()
                }
            }
        }
    }

    // MARK: off state

    private var setup: some View {
        Tile(padding: 26) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 14) {
                    Image(systemName: "sparkles").font(.system(size: 22))
                        .foregroundStyle(Theme.text)
                        .frame(width: 52, height: 52)
                        .background(RoundShape().fill(Theme.inset))
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Advisor is off").font(.display(24)).foregroundStyle(Theme.text)
                        Text("An optional AI that explains a finding and proposes a fix you approve.")
                            .font(.ui(13)).foregroundStyle(Theme.text3)
                    }
                }
                Text("Turn it on, choose a provider and a model, then add a key — or point it at a local model so nothing leaves this Mac. A finding is only sent when you press Ask or Brief me.")
                    .font(.ui(13.5)).foregroundStyle(Theme.text2)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 680, alignment: .leading)
                HStack(spacing: 8) {
                    Button("Enable now") {
                        Task { await store.setAdvisorEnabled(true) }
                    }
                    .buttonStyle(CoralButtonStyle(compact: true))
                    Button("Open Settings") { store.screen = .settings }
                        .buttonStyle(GhostButtonStyle(compact: true))
                }
            }
        }
    }
}
