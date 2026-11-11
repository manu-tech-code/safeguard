import SwiftUI

struct StartupView: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        let s = store.status!
        let items = s.launchItems.sorted {
            (($0.known && !$0.changed) ? 1 : 0, $0.scope, $0.label) < (($1.known && !$1.changed) ? 1 : 0, $1.scope, $1.label)
        }
        let fresh = s.launchItems.filter { !$0.known || $0.changed }.count
        let present = s.files.filter { $0.state != "absent" }
        let changed = present.filter { ["modified", "created", "deleted"].contains($0.state) }.count
        let files = s.files.sorted { (fileRank($0), $0.path) < (fileRank($1), $1.path) }

        ScreenScaffold(.startup) {
            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    StatTile("Launch items", value: "\(s.launchItems.count)",
                             caption: fresh > 0 ? "\(fresh) new" : "Unchanged",
                             captionColor: fresh > 0 ? Theme.accentText : Theme.text3)
                    StatTile("Sensitive files intact", value: "\(present.count - changed)/\(present.count)",
                             caption: changed > 0 ? "\(changed) changed" : nil, captionColor: Theme.amber)
                    StatTile("System extensions", value: "\(s.systemExtensions.count)")
                    StatTile("Scheduled jobs", value: "\(s.crontab.count)")
                }
                .frame(height: 132)

                Tile(padding: 22) {
                    VStack(alignment: .leading, spacing: 8) {
                        TileHeader("Launch agents and daemons",
                                   caption: "Programs macOS starts automatically. Malware almost always installs itself here.")
                            .padding(.bottom, 6)
                        if items.isEmpty {
                            EmptyNote(symbol: "power", title: "No launch items", message: "Nothing starts automatically.")
                        }
                        ForEach(items) { LaunchItemRow(item: $0) }
                    }
                }

                loginItemsTile(s)

                HStack(alignment: .top, spacing: 12) {
                    Tile(padding: 22) {
                        VStack(alignment: .leading, spacing: 8) {
                            TileHeader("Sensitive files", caption: "Fingerprinted at baseline. Any edit shows up here.")
                                .padding(.bottom, 6)
                            ForEach(files) { FileRow(file: $0) }
                        }
                    }
                    Tile(padding: 22) {
                        VStack(alignment: .leading, spacing: 16) {
                            TileHeader("Deep system access", caption: "Extensions and scheduled jobs")
                            VStack(alignment: .leading, spacing: 8) {
                                Text("System extensions").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                                if s.systemExtensions.isEmpty {
                                    Text("None enabled.").font(.ui(13)).foregroundStyle(Theme.text2).insetRow()
                                }
                                ForEach(s.systemExtensions, id: \.self) { ext in
                                    Text(ext).font(.mono(11.5)).foregroundStyle(Theme.text).lineLimit(1).insetRow()
                                }
                            }
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Cron jobs").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                                if s.crontab.isEmpty {
                                    HStack(spacing: 10) {
                                        Dot(color: Theme.green)
                                        Text("None. Good: malware likes cron.").font(.ui(13)).foregroundStyle(Theme.text2)
                                    }
                                    .insetRow()
                                }
                                ForEach(s.crontab, id: \.self) { line in
                                    Text(line).font(.mono(11)).foregroundStyle(Theme.amber).insetRow()
                                }
                            }
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Ransomware tripwires").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                                if let canaries = s.canaries, !canaries.isEmpty {
                                    let intact = canaries.filter(\.intact).count
                                    HStack(spacing: 10) {
                                        Dot(color: intact == canaries.count ? Theme.green : Theme.red)
                                        Text(intact == canaries.count
                                             ? "\(intact)/\(canaries.count) intact"
                                             : "\(canaries.count - intact) changed or missing")
                                            .font(.ui(13)).foregroundStyle(Theme.text2)
                                    }
                                    .insetRow()
                                } else {
                                    Text("Not installed. Plant them with: safeguard.py canary --install")
                                        .font(.ui(13)).foregroundStyle(Theme.text2)
                                        .fixedSize(horizontal: false, vertical: true)
                                        .insetRow()
                                }
                            }
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Installed apps").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                                Text("\(s.appsCount) in Applications. New installs are logged as findings.")
                                    .font(.ui(13)).foregroundStyle(Theme.text2)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .insetRow()
                            }
                        }
                    }
                    .frame(width: 380)
                }
                .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder
    private func loginItemsTile(_ s: ScanStatus) -> some View {
        Tile(padding: 22) {
            VStack(alignment: .leading, spacing: 10) {
                TileHeader("Hidden login items",
                           caption: "macOS keeps these behind an administrator prompt, so Safeguard no longer asks on every scan.")
                if store.loginItemsBusy {
                    HStack(spacing: 10) {
                        Spinner(color: Theme.text2, size: 10)
                        Text("Asking macOS…").font(.ui(13)).foregroundStyle(Theme.text2)
                    }
                    .insetRow()
                } else if let hidden = s.backgroundItems, !hidden.isEmpty {
                    let notable = hidden.filter(\.enabled)
                        .sorted { ($0.known ? 1 : 0, $0.label) < ($1.known ? 1 : 0, $1.label) }
                    ForEach(notable.prefix(8)) { item in
                        HStack(spacing: 14) {
                            Dot(color: item.known ? Theme.text3 : Theme.amber)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 7) {
                                    Text(item.label).font(.ui(13.5, 600))
                                        .foregroundStyle(Theme.text).lineLimit(1)
                                    if !item.known {
                                        Pill("New", color: Theme.accentText, fill: Theme.accent.opacity(0.14))
                                    }
                                }
                                Text(item.developerLabel).font(.ui(12))
                                    .foregroundStyle(Theme.text3).lineLimit(1)
                            }
                            Spacer()
                            PathText(item.path.isEmpty ? item.key : item.path, size: 10.5)
                                .frame(maxWidth: 260, alignment: .trailing)
                        }
                        .insetRow(padding: EdgeInsets(top: 9, leading: 14, bottom: 9, trailing: 14))
                    }
                    if let checked = s.loginItemsChecked {
                        Text("Checked \(Fmt.relative(Fmt.date(checked)))").font(.ui(11.5)).foregroundStyle(Theme.dim)
                            .padding(.leading, 14)
                    }
                } else {
                    Text("Not checked on this Mac. Reading the list needs your administrator password, so it only runs when you press the button.")
                        .font(.ui(13)).foregroundStyle(Theme.text2)
                        .fixedSize(horizontal: false, vertical: true)
                        .insetRow()
                }
                HStack(spacing: 10) {
                    Button(s.backgroundItems?.isEmpty == false ? "Check again" : "Check login items") {
                        Task { await store.checkLoginItems() }
                    }
                    .buttonStyle(GhostButtonStyle(compact: true))
                    .disabled(store.loginItemsBusy)
                    Text("macOS will ask once; you can cancel.")
                        .font(.ui(11.5)).foregroundStyle(Theme.text3)
                }
                .padding(.leading, 14)
            }
        }
    }

    private func fileRank(_ f: WatchedFile) -> Int {
        switch f.state {
        case "modified", "created", "deleted": 0
        case "unchanged": 1
        case "unwatched": 2
        default: 3
        }
    }
}

struct LaunchItemRow: View {
    @Environment(AppStore.self) private var store
    let item: LaunchItem

    var body: some View {
        HStack(spacing: 14) {
            ProgramIcon(path: item.program, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Text(item.label).font(.ui(13.5, 600)).foregroundStyle(Theme.text).lineLimit(1)
                    if !item.known { Pill("New", color: Theme.accentText, fill: Theme.accent.opacity(0.14)) }
                    if item.changed { Pill("Modified", color: Theme.amber, fill: Theme.amber.opacity(0.14)) }
                }
                PathText(item.program.isEmpty ? item.path : item.program, size: 10.5)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Pill(item.scope == "user" ? "Your account" : item.scope == "daemon" ? "System" : "All users")
            SignatureLabel(signature: item.signature).frame(width: 190, alignment: .leading)
            Button { store.reveal(item.path) } label: { Image(systemName: "folder") }
                .buttonStyle(RoundIconButtonStyle())
                .help("Show the launch file in Finder")
        }
        .insetRow(padding: EdgeInsets(top: 10, leading: 14, bottom: 10, trailing: 10))
    }
}

struct FileRow: View {
    let file: WatchedFile

    private var look: (color: Color, label: String) {
        switch file.state {
        case "unchanged": (Theme.green, "Intact")
        case "modified": (Theme.amber, "Modified")
        case "created": (Theme.amber, "Created")
        case "deleted": (Theme.red, "Deleted")
        case "unwatched": (Theme.blue, "New to watch")
        default: (Theme.text3, "Not present")
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Dot(color: look.color)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Text(Fmt.tilde(file.path)).font(.mono(12))
                        .foregroundStyle(file.state == "absent" ? Theme.text3 : Theme.text)
                    if file.severity == .high { Pill("Critical") }
                }
                Text(file.why.prefix(1).uppercased() + file.why.dropFirst()).font(.ui(12)).foregroundStyle(Theme.text3)
                    .lineLimit(1)
            }
            Spacer()
            Text(look.label).font(.ui(12.5, 600)).foregroundStyle(file.state == "unchanged" ? Theme.text2 : look.color).labelCase()
        }
        .insetRow(padding: EdgeInsets(top: 9, leading: 14, bottom: 9, trailing: 14))
    }
}
