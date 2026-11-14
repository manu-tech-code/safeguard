import AppKit
import SwiftUI

struct ThreatsView: View {
    @Environment(AppStore.self) private var store
    @State private var filter: Severity? = nil
    @State private var showReviewed = false
    @State private var query = ""
    @State private var showDigest = false
    @State private var selection = Set<String>()
    @State private var lastClicked: Int?

    private var alerts: [ThreatAlert] {
        (store.status?.alerts ?? [])
            .filter { showReviewed || !$0.isAcked }
            .filter { filter == nil || $0.severity == filter }
            .filter { query.isEmpty || ($0.title + $0.detail).localizedCaseInsensitiveContains(query) }
            .sorted { ($0.isAcked ? 1 : 0, -$0.severity.rank) < ($1.isAcked ? 1 : 0, -$1.severity.rank) }
    }

    private var selected: ThreatAlert? {
        alerts.first { $0.id == store.selectedAlertID } ?? alerts.first
    }

    private var allSelected: Bool { !alerts.isEmpty && selection.count == alerts.count }

    private func toggle(_ alert: ThreatAlert, at index: Int) {
        if NSEvent.modifierFlags.contains(.shift), let from = lastClicked, from != index {
            let range = from < index ? from...index : index...from
            selection.formUnion(alerts[range].map(\.id))
        } else if selection.contains(alert.id) {
            selection.remove(alert.id)
        } else {
            selection.insert(alert.id)
        }
        lastClicked = index
    }

    private func applySelection(reviewed: Bool) {
        let ids = Array(selection)
        Task {
            await store.setAcknowledged(ids, reviewed)
            selection.subtract(ids)
        }
    }

    @ViewBuilder
    private var selectionBar: some View {
        HStack(spacing: 10) {
            Button(allSelected ? "Deselect all" : "Select all") {
                selection = allSelected ? [] : Set(alerts.map(\.id))
            }
            .buttonStyle(GhostButtonStyle(compact: true))
            .fixedSize()

            if !selection.isEmpty {
                Spacer(minLength: 0)
                Button("Mark \(selection.count) reviewed") { applySelection(reviewed: true) }
                    .buttonStyle(LightButtonStyle(compact: true))
                    .fixedSize()
                Button("Unmark") { applySelection(reviewed: false) }
                    .buttonStyle(GhostButtonStyle(compact: true))
                    .fixedSize()
            } else {
                Spacer(minLength: 0)
                Text("Shift-click for a range")
                    .font(.ui(11.5)).foregroundStyle(Theme.dim).lineLimit(1)
            }
        }
    }

    var body: some View {
        ScreenScaffold(.threats, scrolls: false) {
            HStack(alignment: .top, spacing: 12) {
                Tile(padding: 16) {
                    VStack(alignment: .leading, spacing: 12) {
                        Segmented(options: [(nil, "All \(countFor(nil))"),
                                            (.high, "High \(countFor(.high))"),
                                            (.medium, "Medium \(countFor(.medium))"),
                                            (.low, "Low \(countFor(.low))")],
                                  selection: $filter)
                        HStack(spacing: 12) {
                            SearchField(text: $query, placeholder: "Search findings")
                            Toggle(isOn: $showReviewed) {
                                Text("Reviewed").font(.ui(12.5)).foregroundStyle(Theme.text2)
                            }
                            .toggleStyle(SwitchStyle())
                            .fixedSize()
                        }
                        if store.advisor?.enabled == true {
                            Button {
                                showDigest = true
                            } label: {
                                Label("Brief me on this scan", systemImage: "sparkles")
                            }
                            .buttonStyle(GhostButtonStyle(compact: true))
                        }
                        if !alerts.isEmpty { selectionBar }
                        if alerts.isEmpty {
                            EmptyNote(symbol: "checkmark.shield", title: "Nothing here",
                                      message: query.isEmpty && filter == nil
                                          ? "No findings since your baseline."
                                          : "No findings match this filter.")
                            Spacer()
                        } else {
                            ScrollView {
                                LazyVStack(spacing: 8) {
                                    ForEach(Array(alerts.enumerated()), id: \.element.id) { index, a in
                                        HStack(spacing: 10) {
                                            SelectBox(on: selection.contains(a.id)) { toggle(a, at: index) }
                                            ThreatRow(alert: a, selected: a.id == selected?.id)
                                                .contentShape(Rectangle())
                                                .onTapGesture {
                                                    lastClicked = index
                                                    store.selectedAlertID = a.id
                                                }
                                        }
                                    }
                                }
                            }
                            .scrollIndicators(.never)
                        }
                    }
                }
                .frame(width: 450)
                .frame(maxHeight: .infinity)

                if let alert = selected {
                    ThreatDetail(alert: alert).id(alert.id)
                        .frame(maxHeight: .infinity)
                } else {
                    Tile {
                        EmptyNote(symbol: "shield", title: "Nothing to review",
                                  message: "When something changes on your Mac, the details and what to do about it appear here.")
                            .frame(maxHeight: .infinity)
                    }
                }
            }
        }
        .sheet(isPresented: $showDigest) { AdvisorDigestSheet() }
        .onChange(of: alerts.map(\.id)) { _, ids in
            selection.formIntersection(Set(ids))
        }
        .task {
            // Snapshot hook: show the bulk bar populated.
            if ProcessInfo.processInfo.environment["SAFEGUARD_SELECT_MANY"] == "1", selection.isEmpty {
                selection = Set(alerts.prefix(3).map(\.id))
            }
        }
    }

    private func countFor(_ s: Severity?) -> Int {
        (store.status?.alerts ?? []).filter { (showReviewed || !$0.isAcked) && (s == nil || $0.severity == s) }.count
    }
}

struct ThreatDetail: View {
    @Environment(AppStore.self) private var store
    let alert: ThreatAlert

    private var ink: Color { Theme.skin.heroFilled ? Theme.onFill : Theme.text }

    var body: some View {
        Tile(padding: 12) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 8) {
                            HeroBadge(text: "\(alert.severity.label) severity", color: alert.severity.color,
                                      ink: Theme.onFill, size: 12.5)
                            Text(alert.kindLabel).font(.ui(12.5, 500)).foregroundStyle(ink.opacity(0.75))
                            Spacer()
                            if alert.isNew { Text("New").font(.ui(12.5, 600)).foregroundStyle(ink) }
                            if alert.isAcked { Text("Reviewed").font(.ui(12.5, 600)).foregroundStyle(ink) }
                        }
                        Text(alert.title).font(.display(28)).foregroundStyle(ink)
                            .fixedSize(horizontal: false, vertical: true)
                        if let first = Fmt.date(alert.firstSeen) {
                            Text("First seen \(Fmt.dateTime(first)), \(Fmt.relative(first))")
                                .font(.ui(12.5)).foregroundStyle(ink.opacity(0.7))
                        }
                    }
                    .padding(22)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .heroSurface(alert.severity.fill)

                    VStack(alignment: .leading, spacing: 18) {
                        if let path = alert.programPath, alert.kind == "conn" || alert.kind == "persist" {
                            HStack(spacing: 12) {
                                ProgramIcon(path: path, size: 34)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(Fmt.programName(path)).font(.ui(14, 600)).foregroundStyle(Theme.text)
                                    PathText(path)
                                }
                            }
                            .insetRow()
                        }

                        VStack(alignment: .leading, spacing: 8) {
                            Text("What Safeguard found").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                            Text(alert.detail)
                                .font(.mono(12))
                                .foregroundStyle(Theme.text)
                                .lineSpacing(3)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(16)
                                .background(RoundedRectangle(cornerRadius: Theme.corner(14), style: .continuous).fill(Theme.well))
                        }

                        VStack(alignment: .leading, spacing: 8) {
                            Text("What to do").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                            Text(alert.appAdvice).font(.ui(14)).foregroundStyle(Theme.text).lineSpacing(3)
                                .frame(maxWidth: 640, alignment: .leading)
                                .fixedSize(horizontal: false, vertical: true)
                        }

                        if store.advisor?.enabled == true {
                            AdvisorPanel(alert: alert)
                        }

                        actions.padding(.top, 4)

                        Text(alert.id).font(.mono(10)).foregroundStyle(Theme.dim).textSelection(.enabled)
                            .lineLimit(2).truncationMode(.middle)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .padding(.bottom, 10)
                }
            }
            .scrollIndicators(.never)
        }
        .frame(maxHeight: .infinity)
    }

    private var actions: some View {
        HStack(spacing: 8) {
            Button(alert.isAcked ? "Move back to active" : "Mark as reviewed") {
                Task { await store.setAcknowledged(alert, !alert.isAcked) }
            }
            .buttonStyle(LightButtonStyle())

            if alert.kind == "conn", let path = alert.subjectPath {
                Button("Trust program") {
                    store.confirm = ConfirmRequest(
                        title: "Trust \(Fmt.programName(path))?",
                        message: "Safeguard will stop raising network alerts for this program. Only do this if you know what it is, for example a tool you built or installed yourself.\n\n\(path)",
                        action: "Trust program") { await store.trust(path) }
                }
                .buttonStyle(GhostButtonStyle())
            }

            if let path = alert.subjectPath, FileManager.default.fileExists(atPath: path) {
                Button("Show in Finder") { store.reveal(path) }.buttonStyle(GhostButtonStyle())
            }

            Spacer()

            if ["persist", "file", "cron", "listen", "app", "sysext"].contains(alert.kind) {
                Button("Accept all changes") {
                    store.confirm = ConfirmRequest(
                        title: "Accept everything as normal?",
                        message: "This saves a new baseline: every current startup item, file, port and app becomes the new normal, and all current findings are cleared. Only do this once you've reviewed them.",
                        action: "Save new baseline", destructive: true) { await store.rebaseline() }
                }
                .buttonStyle(TextLinkStyle(color: Theme.text2))
            }
        }
    }
}
