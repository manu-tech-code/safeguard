import AppKit
import SwiftUI

struct BrowserVisit: Codable, Hashable, Identifiable {
    var browser: String
    var profile: String?
    var url: String
    var domain: String
    var title: String
    var at: String
    var ts: Double
    var id: String { browser + "|" + at + "|" + url }
}

struct BrowserSite: Codable, Hashable, Identifiable {
    var domain: String
    var visits: Int
    var last: String
    var first: String
    var browsers: [String]
    var id: String { domain }
}

struct BrowserToday: Codable, Hashable {
    var domains: Int
    var visits: Int
}

struct BrowserSource: Codable, Hashable, Identifiable {
    var browser: String
    var kind: String?
    var found: Bool?
    var profiles: Int?
    var status: String
    var id: String { browser }
}

struct BrowserRequest: Codable, Hashable, Identifiable {
    var id: String
    var ts: Double
    var browser: String
    var tab: Int?
    var type: String
    var method: String
    var url: String
    var domain: String
    var status: Int?
    var action: String
    var reason: String?
    var hidden: Bool?
}

struct BrowserRules: Codable, Hashable {
    var block: [String]
    var warn: [String]
}

struct BridgeHealth: Codable, Hashable {
    var ok: Bool?
    var service: String?
}

struct BrowserExtension: Codable, Hashable {
    var ok: Bool
    var path: String?
}

struct BrowserExtensionState: Codable, Hashable {
    var lastSeen: String?
    var ageSeconds: Int?
    var browser: String?
    var version: String?
    var stale: Bool?
    var lastRequest: String?
}

struct BrowserOverview: Codable, Hashable {
    var ok: Bool
    var days: Int?
    var retentionDays: Int?
    var visits: [BrowserVisit]?
    var sites: [BrowserSite]?
    var today: BrowserToday?
    var sources: [BrowserSource]?
    var requests: [BrowserRequest]?
    var rules: BrowserRules?
    var bridge: BridgeHealth?
    var requestRetentionDays: Int?
    var extensionPath: String?
    var ext: BrowserExtensionState?
}

struct BrowserConfig: Codable, Hashable {
    var enabled: Bool?
    var retentionDays: Int?
}

struct BrowserSyncResult: Codable, Hashable {
    var ok: Bool?
    var new: Int?
    var checked: Int?
    var errors: [String]?
}

enum BrowserMode: String, Hashable, CaseIterable { case visits, requests, rules }
enum RequestFilter: String, Hashable, CaseIterable { case all, flagged, hidden }

struct SweepSite: Codable, Hashable, Identifiable {
    var domain: String
    var verdict: String
    var why: String?
    var action: String?
    var confidence: Double?
    var id: String { domain }
}

struct BrowserSweep: Codable, Hashable {
    var ok: Bool
    var error: String?
    var summary: String?
    var sites: [SweepSite]?
    var checked: Int?
    var model: String?
}

struct BrowserView: View {
    @Environment(AppStore.self) private var store

    @State private var search = ""
    @State private var selectedDomain: String?
    @State private var selectedRequestID: String?
    @State private var mode: BrowserMode =
        BrowserMode(rawValue: ProcessInfo.processInfo.environment["SAFEGUARD_BROWSER_MODE"] ?? "") ?? .visits
    @State private var requestFilter: RequestFilter = .all
    @State private var browserFilter: String?
    @State private var showSweep = false
    @State private var blockText = ""
    @State private var warnText = ""

    private var sources: [BrowserSource] { store.browser?.sources ?? [] }
    private var denied: [BrowserSource] { sources.filter { $0.status == "denied" } }
    private var visits: [BrowserVisit] { store.browser?.visits ?? [] }
    private var sites: [BrowserSite] { store.browser?.sites ?? [] }
    private var chosen: BrowserSite? {
        sites.first { $0.domain == selectedDomain } ?? sites.first
    }
    private var siteVisits: [BrowserVisit] {
        guard let domain = chosen?.domain else { return [] }
        return visits.filter { $0.domain == domain }
    }

    private var ext: BrowserExtensionState? { store.browser?.ext }
    /// Silent failure looks identical to "nothing happened", so say which one it is.
    private var showExtensionNotice: Bool { ext?.stale ?? true }

    private func ageText(_ seconds: Int?) -> String {
        guard let seconds else { return "never" }
        if seconds < 90 { return "just now" }
        if seconds < 3600 { return "\(seconds / 60) min ago" }
        if seconds < 172_800 { return "\(seconds / 3600) h ago" }
        let days = seconds / 86_400
        return days == 1 ? "yesterday" : "\(days) days ago"
    }

    @ViewBuilder
    private var extensionNotice: some View {
        let name = ext?.browser.map { "\($0) extension" } ?? "browser extension"
        HStack(spacing: 10) {
            Image(systemName: "antenna.radiowaves.left.and.right.slash")
                .font(.system(size: 13)).foregroundStyle(Theme.amber)
            VStack(alignment: .leading, spacing: 2) {
                Text(ext == nil || ext?.lastSeen == nil
                     ? "No browser extension has connected yet"
                     : "\(name) last seen \(ageText(ext?.ageSeconds))")
                    .font(.ui(13, 600)).foregroundStyle(Theme.text)
                Text(ext == nil || ext?.lastSeen == nil
                     ? "Live requests only come from the Chrome, Edge, Brave, Arc or Vivaldi extension. Install it below, then keep the browser open."
                     : "Live requests resume when that browser is open with the extension loaded. Sites visited in Safari or Firefox appear under Visits only.")
                    .font(.ui(11.5)).foregroundStyle(Theme.text3)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if let path = store.browser?.extensionPath {
                Button("Show folder") { store.reveal(path) }
                    .buttonStyle(GhostButtonStyle(compact: true))
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: Theme.corner(11), style: .continuous)
            .fill(Theme.amber.opacity(0.12)))
    }

    var body: some View {
        ScreenScaffold(.browser, scrolls: false) {
            VStack(spacing: 12) {
                summary
                    .fixedSize(horizontal: false, vertical: true)
                Segmented(options: BrowserMode.allCases.map { ($0, $0.rawValue.capitalized) },
                          selection: $mode)
                switch mode {
                case .visits:
                    if !denied.isEmpty {
                        HStack(spacing: 10) {
                            Image(systemName: "lock.slash").font(.system(size: 13)).foregroundStyle(Theme.amber)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("\(denied.map(\.browser).joined(separator: ", ")) history is blocked by macOS")
                                    .font(.ui(13, 600)).foregroundStyle(Theme.text)
                                Text("Visits stay frozen until Safeguard has Full Disk Access. Requests from the extension are unaffected.")
                                    .font(.ui(11.5)).foregroundStyle(Theme.text3)
                            }
                            Spacer()
                            Button("Open Full Disk Access") {
                                if let url = URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles") {
                                    NSWorkspace.shared.open(url)
                                }
                            }
                            .buttonStyle(GhostButtonStyle(compact: true))
                        }
                        .padding(12)
                        .background(RoundedRectangle(cornerRadius: Theme.corner(11), style: .continuous)
                            .fill(Theme.amber.opacity(0.12)))
                    }
                    HStack(alignment: .top, spacing: 12) {
                        visitList.frame(width: 470)
                        detail.frame(maxHeight: .infinity)
                    }
                    .frame(maxHeight: .infinity)
                    sourcesPane
                        .fixedSize(horizontal: false, vertical: true)
                case .requests:
                    if showExtensionNotice { extensionNotice }
                    HStack(alignment: .top, spacing: 12) {
                        requestList.frame(maxHeight: .infinity)
                        if chosenRequest != nil {
                            requestDetail.frame(width: 400)
                                .frame(maxHeight: .infinity)
                        }
                    }
                    .frame(maxHeight: .infinity)
                case .rules:
                    rulesPane
                }
            }
        }
        .sheet(isPresented: $showSweep) { BrowserSweepSheet() }
        .task {
            await store.loadBrowser()
            syncRulesText()
            if ProcessInfo.processInfo.environment["SAFEGUARD_SELECT_FIRST"] == "1" {
                selectedRequestID = store.browser?.requests?.first?.id
            }
        }
        .task(id: mode) {
            switch mode {
            case .requests:
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(2))
                    if Task.isCancelled { break }
                    await store.loadBrowser(silent: true)
                }
            case .visits:
                while !Task.isCancelled {
                    await store.loadBrowser(silent: true, refreshVisits: true)
                    try? await Task.sleep(for: .seconds(2))
                }
            case .rules:
                break
            }
        }
        .onChange(of: mode) { _, newValue in
            if newValue == .rules { syncRulesText() }
        }
    }

    private func syncRulesText() {
        blockText = (store.browser?.rules?.block ?? []).joined(separator: "\n")
        warnText = (store.browser?.rules?.warn ?? []).joined(separator: "\n")
    }

    // MARK: requests

    private var chosenRequest: BrowserRequest? {
        guard let selectedRequestID else { return nil }
        return (store.browser?.requests ?? []).first { $0.id == selectedRequestID }
    }

    private var distinctBrowsers: [String] {
        Array(Set((store.browser?.requests ?? []).map(\.browser))).sorted()
    }

    private var requests: [BrowserRequest] {
        (store.browser?.requests ?? []).filter { req in
            let browserOK = browserFilter == nil || req.browser == browserFilter
            switch requestFilter {
            case .all: return browserOK
            case .flagged: return browserOK && req.action != "allow"
            case .hidden: return browserOK && req.hidden == true
            }
        }
    }

    private var requestList: some View {
        Tile(padding: 18) {
            VStack(alignment: .leading, spacing: 9) {
                let bridgeOn = store.browser?.bridge?.service == "safeguard"
                HStack(spacing: 10) {
                    Text("Every request · \(store.browser?.requests?.count ?? 0) recorded")
                        .font(.ui(12.5, 500)).foregroundStyle(Theme.text3).lineLimit(1)
                    Spacer(minLength: 6)
                    Button("Refresh") { Task { await store.loadBrowser() } }
                        .buttonStyle(GhostButtonStyle(compact: true)).fixedSize()
                }
                HStack(spacing: 8) {
                    Segmented(options: [(RequestFilter.all, "All"), (.flagged, "Flagged"), (.hidden, "Hidden")],
                              selection: $requestFilter)
                    ThemeMenu(placeholder: "All browsers", items: distinctBrowsers,
                              title: { $0 }, selection: $browserFilter)
                    Spacer(minLength: 0)
                }
                HStack(spacing: 8) {
                    Dot(color: bridgeOn ? (showExtensionNotice ? Theme.amber : Theme.green) : Theme.text3, size: 7)
                    Text(bridgeOn
                         ? (showExtensionNotice ? "Bridge ready, no extension connected" : "Live monitoring is ready")
                         : "Extension bridge is not running")
                        .font(.ui(12)).foregroundStyle(Theme.text3).lineLimit(1)
                    Spacer(minLength: 6)
                    if !bridgeOn {
                        Button("Install extension") { Task { await store.installBrowserExtension() } }
                            .buttonStyle(GhostButtonStyle(compact: true)).fixedSize()
                    }
                }
                Text("Requests come from the Chromium extension; Safari and Firefox only contribute visits.")
                    .font(.ui(10.5)).foregroundStyle(Theme.dim).lineLimit(2)
                if requests.isEmpty {
                    let total = store.browser?.requests?.count ?? 0
                    EmptyNote(symbol: "network.badge.shield.half.filled",
                              title: total > 0 ? "Filters hide all \(total) requests" : "No requests recorded",
                              message: total > 0
                                  ? "Turn off Flagged or Hidden only to see them."
                                  : "Install the Safeguard extension in Chrome, Arc, Brave or Edge, then browse. Every request, including hidden beacons and XHR, appears here.")
                        .frame(maxHeight: .infinity)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 5) {
                            ForEach(requests) { request in
                                Button { selectedRequestID = request.id } label: {
                                    requestRow(request, selected: request.id == chosenRequest?.id)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    .scrollIndicators(.never)
                }
            }
        }
    }

    private func requestRow(_ request: BrowserRequest, selected: Bool) -> some View {
        HStack(spacing: 10) {
            Text(Fmt.time(Date(timeIntervalSince1970: request.ts)))
                .font(.ui(11)).monospacedDigit().foregroundStyle(Theme.text3)
                .frame(width: 56, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(request.domain).font(.ui(12.5, 500)).foregroundStyle(Theme.text)
                        .lineLimit(1)
                    if request.hidden == true { Pill("hidden") }
                    Spacer(minLength: 4)
                    Text(request.browser).font(.ui(10.5)).foregroundStyle(Theme.text2).lineLimit(1)
                    actionBadge(request.action)
                }
                HStack(spacing: 8) {
                    Text(request.method).font(.mono(10.5)).foregroundStyle(Theme.text3)
                    Text(request.type).font(.ui(10.5)).foregroundStyle(Theme.text3).lineLimit(1)
                    Text(request.url).font(.mono(10)).foregroundStyle(Theme.text3)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(CapShape(radius: 8).fill(selected ? Theme.inset : Theme.inset.opacity(0.55)))
    }

    private var requestDetail: some View {
        Tile(padding: 18) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                if let request = chosenRequest {
                    HStack(spacing: 8) {
                        Pill(request.action == "block" ? "blocked" : request.action == "warn" ? "warned" : "allowed",
                             color: request.action == "block" ? Theme.red : request.action == "warn" ? Theme.amber : Theme.text3)
                        if request.hidden == true { Pill("hidden") }
                        Spacer(minLength: 4)
                        Button("Open") {
                            if let url = URL(string: request.url.replacingOccurrences(of: "…", with: "")) {
                                NSWorkspace.shared.open(url)
                            }
                        }
                        .buttonStyle(GhostButtonStyle(compact: true)).fixedSize()
                        Button {
                            selectedRequestID = nil
                        } label: {
                            Image(systemName: "xmark").font(.system(size: 10, weight: .semibold))
                        }
                        .buttonStyle(GhostButtonStyle(compact: true))
                        .help("Close")
                    }
                    Text(request.domain).font(.display(22)).foregroundStyle(Theme.text)
                    Text(request.url).font(.mono(11)).foregroundStyle(Theme.text3)
                        .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                    HStack(spacing: 12) {
                        Text(request.method).font(.mono(11)).foregroundStyle(Theme.text3)
                        Text(request.type).font(.ui(11)).foregroundStyle(Theme.text3).lineLimit(1)
                        Text(request.browser).font(.ui(11.5)).foregroundStyle(Theme.text2).lineLimit(1)
                        if let status = request.status, status > 0 {
                            Text("HTTP \(status)").font(.ui(11.5)).foregroundStyle(Theme.text3).lineLimit(1)
                        }
                        Spacer(minLength: 0)
                    }
                    if let reason = request.reason, !reason.isEmpty {
                        Text(reason).font(.ui(12)).foregroundStyle(Theme.amber)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Rectangle().fill(Theme.line).frame(height: 1).opacity(0.6)
                    AdvisorRequestPanel(request: request)
                } else {
                    EmptyNote(symbol: "sparkles", title: "Pick a request",
                              message: "Select one on the left to verify where it went.")
                }
                }
                .padding(.bottom, 8)
            }
            .scrollIndicators(.never)
        }
    }

    private func actionBadge(_ action: String) -> some View {
        let color: Color = action == "block" ? Theme.red : action == "warn" ? Theme.amber : Theme.text3
        return Text(action == "allow" ? "allowed" : action == "block" ? "blocked" : "warned")
            .font(.ui(10.5, 600)).foregroundStyle(color)
            .frame(width: 54, alignment: .trailing)
    }

    // MARK: rules

    private var rulesPane: some View {
        HStack(alignment: .top, spacing: 12) {
            ruleEditor(title: "Block", hint: "One domain per line. The extension cancels these before they load.",
                       text: $blockText, color: Theme.red)
            ruleEditor(title: "Warn", hint: "The extension shows a warning page first, with Continue once.",
                       text: $warnText, color: Theme.amber)
        }
    }

    private func ruleEditor(title: String, hint: String, text: Binding<String>, color: Color) -> some View {
        Tile(padding: 18) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Dot(color: color, size: 8)
                    Text(title).font(.ui(14, 600)).foregroundStyle(Theme.text)
                    Spacer()
                    let count = text.wrappedValue.split(separator: "\n").count
                    Text("\(count) \(count == 1 ? "entry" : "entries")")
                        .font(.ui(11)).foregroundStyle(Theme.text3)
                }
                Text(hint).font(.ui(11.5)).foregroundStyle(Theme.text3)
                    .fixedSize(horizontal: false, vertical: true)
                TextEditor(text: text)
                    .font(.mono(12))
                    .foregroundStyle(Theme.text)
                    .scrollContentBackground(.hidden)
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: Theme.corner(10), style: .continuous)
                        .fill(Theme.well))
                    .frame(minHeight: 180)
                HStack {
                    Button("Save rules") {
                        let block = blockText.split(separator: "\n").map(String.init)
                        let warn = warnText.split(separator: "\n").map(String.init)
                        Task { await store.saveBrowserRules(block: block, warn: warn) }
                    }
                    .buttonStyle(LightButtonStyle(compact: true))
                    Button("Reload") { syncRulesText() }
                        .buttonStyle(GhostButtonStyle(compact: true))
                    Spacer()
                }
                Divider().opacity(0.2)
                HStack(spacing: 8) {
                    Dot(color: store.browser?.bridge?.service == "safeguard" ? Theme.green : Theme.text3, size: 7)
                    Text(store.browser?.bridge?.service == "safeguard" ? "Bridge running" : "Bridge starting…")
                        .font(.ui(11.5)).foregroundStyle(Theme.text3)
                    Spacer()
                    Button("Install extension") { Task { await store.installBrowserExtension() } }
                        .buttonStyle(GhostButtonStyle(compact: true))
                    Button("Copy path") { store.copyBrowserExtensionPath() }
                        .buttonStyle(GhostButtonStyle(compact: true))
                }
                Text("Extension folder: \(store.browser?.extensionPath ?? "—")")
                    .font(.mono(10)).foregroundStyle(Theme.dim).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(maxHeight: .infinity)
    }

    // MARK: summary

    private var summary: some View {
        Tile(padding: 20) {
            HStack(spacing: 26) {
                stat("Today", "\(store.browser?.today?.visits ?? 0)", "visits")
                stat("Sites", "\(store.browser?.today?.domains ?? 0)", "today")
                stat("Kept", "\(store.browser?.retentionDays ?? 90)", "days")
                Spacer()
                if store.browserLoading || store.sweepBusy { Spinner(color: Theme.text2, size: 10) }
                Button {
                    Task {
                        if await store.sweepBrowser() { showSweep = true }
                    }
                } label: {
                    Label("Security sweep", systemImage: "sparkles")
                }
                .buttonStyle(LightButtonStyle(compact: true))
                .disabled(store.sweepBusy || store.advisor?.enabled != true)
                Button("Import now") { Task { await store.importBrowserNow() } }
                    .buttonStyle(GhostButtonStyle(compact: true))
                    .disabled(store.browserLoading)
            }
        }
    }

    private func stat(_ title: String, _ value: String, _ note: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.ui(11.5)).foregroundStyle(Theme.text3)
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                Text(value).font(.figure(28, 700)).foregroundStyle(Theme.text)
                Text(note).font(.ui(12)).foregroundStyle(Theme.text3)
            }
        }
    }

    // MARK: visits

    private var visitList: some View {
        Tile(padding: 16) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    SearchField(text: $search, placeholder: "Search sites")
                    Button("Search") {
                        store.browserQuery = search
                        Task { await store.loadBrowser() }
                    }
                    .buttonStyle(GhostButtonStyle(compact: true))
                }
                Segmented(options: [(1, "Today"), (7, "7 days"), (30, "30 days")],
                          selection: Binding(get: { store.browserDays },
                                             set: { days in
                                                 store.browserDays = days
                                                 Task { await store.loadBrowser() }
                                             }))
                if let updated = store.browserUpdatedAt {
                    Text("Updated \(Fmt.time(updated))")
                        .font(.ui(10.5)).foregroundStyle(Theme.dim)
                }
                if visits.isEmpty {
                    EmptyNote(symbol: "safari", title: "No visits yet",
                              message: store.browserLoading ? "Reading browser history…"
                                  : "Nothing recorded for this range. Import now, or grant Full Disk Access to Safari and Chrome.")
                        .frame(maxHeight: .infinity)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 6) {
                            ForEach(visits) { visit in
                                Button {
                                    selectedDomain = visit.domain
                                } label: {
                                    row(visit, selected: visit.domain == chosen?.domain)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    .scrollIndicators(.never)
                }
            }
        }
        .frame(maxHeight: .infinity)
    }

    private func row(_ visit: BrowserVisit, selected: Bool) -> some View {
        HStack(spacing: 10) {
            Text(Fmt.date(visit.at).map(Fmt.time) ?? "")
                .font(.ui(11.5)).monospacedDigit().foregroundStyle(Theme.text3)
                .frame(width: 58, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(visit.domain).font(.ui(13, selected ? 600 : 500))
                    .foregroundStyle(Theme.text).lineLimit(1)
                Text(visit.title.isEmpty ? visit.url : visit.title)
                    .font(.ui(11.5)).foregroundStyle(Theme.text3).lineLimit(1)
            }
            Spacer(minLength: 6)
            Text(visit.browser).font(.ui(11)).foregroundStyle(Theme.text3)
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(CapShape(radius: 9).fill(selected ? Theme.inset : .clear))
        .contentShape(Rectangle())
    }

    // MARK: detail

    private var detail: some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 12) {
                if let site = chosen {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text(site.domain).font(.display(24)).foregroundStyle(Theme.text)
                        Spacer()
                        Button("Open site") {
                            if let url = URL(string: "https://" + site.domain) { NSWorkspace.shared.open(url) }
                        }
                        .buttonStyle(GhostButtonStyle(compact: true))
                    }
                    HStack(spacing: 14) {
                        Text("\(site.visits) visits").font(.ui(12.5)).foregroundStyle(Theme.text2)
                        Text("first \(Fmt.date(site.first).map(Fmt.day) ?? site.first)")
                            .font(.ui(12)).foregroundStyle(Theme.text3).lineLimit(1)
                        Text("last \(Fmt.date(site.last).map(Fmt.dateTime) ?? site.last)")
                            .font(.ui(12)).foregroundStyle(Theme.text3).lineLimit(1)
                        Spacer()
                        ForEach(site.browsers, id: \.self) { Pill($0) }
                    }
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(siteVisits) { visit in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(visit.title.isEmpty ? visit.url : visit.title)
                                        .font(.ui(12.5, 500)).foregroundStyle(Theme.text).lineLimit(2)
                                    Text(visit.url).font(.mono(10.5)).foregroundStyle(Theme.text3)
                                        .lineLimit(1).truncationMode(.middle)
                                }
                                .insetRow(padding: EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                            }
                        }
                    }
                    .scrollIndicators(.never)
                } else {
                    EmptyNote(symbol: "safari", title: "Pick a site",
                              message: "Your visit timeline appears on the left.")
                }
            }
        }
    }

    // MARK: sources

    private var sourcesPane: some View {
        Tile(padding: 18) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Where this comes from").font(.ui(12, 500)).foregroundStyle(Theme.text3)
                    Spacer()
                    if !denied.isEmpty {
                        Button("Open Full Disk Access") {
                            if let url = URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles") {
                                NSWorkspace.shared.open(url)
                            }
                        }
                        .buttonStyle(GhostButtonStyle(compact: true))
                    }
                }
                HStack(spacing: 8) {
                    ForEach(sources) { source in
                        HStack(spacing: 6) {
                            Dot(color: color(for: source.status), size: 7)
                            Text(source.browser).font(.ui(12)).foregroundStyle(Theme.text2)
                            if let profiles = source.profiles, profiles > 0 {
                                Text("\(profiles)").font(.ui(11)).foregroundStyle(Theme.text3)
                            }
                        }
                        .padding(.horizontal, 9).padding(.vertical, 5)
                        .background(CapShape(radius: 8).fill(Theme.inset))
                        .help(source.status == "denied"
                              ? "Grant Full Disk Access to Safeguard in System Settings."
                              : source.status)
                    }
                    Spacer()
                }
                if !denied.isEmpty {
                    Text("\(denied.map(\.browser).joined(separator: ", ")) need Full Disk Access. Safeguard only reads these databases; it never changes them.")
                        .font(.ui(11.5)).foregroundStyle(Theme.text3)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func color(for status: String) -> Color {
        switch status {
        case "ok": return Theme.green
        case "denied": return Theme.amber
        case "empty": return Theme.text3
        default: return Theme.dim
        }
    }
}

struct BrowserSweepSheet: View {
    @Environment(AppStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Browser sweep").font(.display(26)).foregroundStyle(Theme.text)
                    Text("The advisor reviewed your recent sites. Nothing changes until you choose.")
                        .font(.ui(12.5)).foregroundStyle(Theme.text3)
                }
                Spacer()
                if store.sweepBusy { Spinner(color: Theme.text2, size: 10) }
                Button("Done") { dismiss() }.buttonStyle(GhostButtonStyle(compact: true))
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let sweep = store.browserSweep {
                        if let summary = sweep.summary, !summary.isEmpty {
                            Text(summary).font(.ui(14)).foregroundStyle(Theme.text)
                                .lineSpacing(3).fixedSize(horizontal: false, vertical: true)
                        }
                        if let sites = sweep.sites, !sites.isEmpty {
                            ForEach(sites) { site in
                                HStack(alignment: .top, spacing: 12) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(site.domain).font(.ui(14, 600)).foregroundStyle(Theme.text)
                                        if let why = site.why, !why.isEmpty {
                                            Text(why).font(.ui(12.5)).foregroundStyle(Theme.text2)
                                                .fixedSize(horizontal: false, vertical: true)
                                        }
                                    }
                                    Spacer()
                                    Pill(site.verdict, color: site.verdict == "risky" ? Theme.red : Theme.amber,
                                         fill: (site.verdict == "risky" ? Theme.red : Theme.amber).opacity(0.14))
                                    HStack(spacing: 6) {
                                        Button("Block") {
                                            Task { await store.applyBrowserRule(domain: site.domain, action: "block") }
                                        }
                                        .buttonStyle(GhostButtonStyle(compact: true))
                                        .disabled(store.fixing)
                                        Button("Warn") {
                                            Task { await store.applyBrowserRule(domain: site.domain, action: "warn") }
                                        }
                                        .buttonStyle(GhostButtonStyle(compact: true))
                                        .disabled(store.fixing)
                                    }
                                }
                                .padding(12)
                                .background(RoundedRectangle(cornerRadius: Theme.corner(11), style: .continuous)
                                    .fill(Theme.inset))
                            }
                        } else {
                            EmptyNote(symbol: "checkmark.shield", title: "Nothing stood out",
                                      message: "No site needed a block or warning.")
                        }
                        Text("Reviewed \(sweep.checked ?? 0) sites\(sweep.model.map { " with \($0)" } ?? "")")
                            .font(.ui(11)).foregroundStyle(Theme.dim)
                    } else {
                        Text("No sweep yet.").font(.ui(13)).foregroundStyle(Theme.text2)
                    }
                }
            }
            .scrollIndicators(.never)
        }
        .padding(24)
        .frame(width: 720, height: 560)
        .background(Color(nsColor: Theme.windowBackground))
    }
}
