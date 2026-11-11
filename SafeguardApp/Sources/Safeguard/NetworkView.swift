import SwiftUI

struct NetworkView: View {
    @Environment(AppStore.self) private var store
    @State private var portFilter = "all"
    @State private var query = ""

    private func risk(_ c: Connection) -> Int {
        switch c.signature {
        case "unsigned": 0
        case "unknown": 1
        case "adhoc": 2
        default: 3
        }
    }

    var body: some View {
        let s = store.status!
        let conns = s.connections
            .filter { query.isEmpty || $0.path.localizedCaseInsensitiveContains(query) }
            .sorted { (risk($0), -$0.remotes.count) < (risk($1), -$1.remotes.count) }
        let ports = s.listening
            .filter { portFilter == "all" || (portFilter == "exposed" && $0.exposed) || (portFilter == "new" && !$0.known) }
            .sorted { ($0.exposed ? 0 : 1, $0.port) < ($1.exposed ? 0 : 1, $1.port) }
        let newPorts = s.listening.filter { !$0.known }.count
        let spark = Array(s.history.suffix(14).map(\.online))

        ScreenScaffold(.network) {
            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    StatTile("Apps online", value: "\(s.connections.count)") {
                        if spark.count > 1 { Spark(values: spark, highlight: Theme.text2, height: 36) }
                    }
                    StatTile("Open connections", value: "\(s.connections.reduce(0) { $0 + $1.remotes.count })")
                    StatTile("Listening ports", value: "\(s.listening.count)",
                             caption: newPorts > 0 ? "\(newPorts) new" : nil, captionColor: Theme.amber)
                    StatTile("Reachable from network", value: "\(s.listening.filter(\.exposed).count)")
                }
                .frame(height: 132)

                Tile(padding: 22) {
                    VStack(alignment: .leading, spacing: 12) {
                        TileHeader("Online now", caption: "Programs with open internet connections, riskiest first") {
                            SearchField(text: $query, placeholder: "Filter programs").frame(width: 220)
                        }
                        .padding(.bottom, 4)
                        if conns.isEmpty {
                            EmptyNote(symbol: "wifi.slash", title: "Nothing online",
                                      message: "No program you run has an open internet connection right now.")
                        }
                        ForEach(conns) { ConnectionRow(connection: $0) }
                        Text("Without administrator rights, macOS only shows your own programs here, not system services.")
                            .font(.ui(12)).foregroundStyle(Theme.text3).padding(.top, 4)
                    }
                }

                Tile(padding: 22) {
                    VStack(alignment: .leading, spacing: 12) {
                        TileHeader("Listening ports", caption: "Doors open on this Mac, and who can knock") {
                            Segmented(options: [("all", "All"), ("exposed", "Reachable"), ("new", "New")],
                                      selection: $portFilter)
                        }
                        .padding(.bottom, 4)
                        if ports.isEmpty {
                            EmptyNote(symbol: "door.left.hand.closed", title: "No matching ports",
                                      message: "Nothing matches this filter.")
                        } else {
                            LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)],
                                      spacing: 8) {
                                ForEach(ports) { ListenerRow(listener: $0) }
                            }
                        }
                    }
                }

                Tile(padding: 22) {
                    VStack(alignment: .leading, spacing: 16) {
                        TileHeader("Name resolution and remote drives",
                                   caption: "Who answers for the names you type, and what is mounted")
                        HStack(alignment: .top, spacing: 24) {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("DNS servers").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                                if let servers = s.dns?.servers, !servers.isEmpty {
                                    ForEach(servers, id: \.self) { server in
                                        Text(server).font(.mono(11.5)).foregroundStyle(Theme.text).insetRow()
                                    }
                                } else {
                                    Text("System default").font(.ui(13)).foregroundStyle(Theme.text2).insetRow()
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Per-domain overrides").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                                if let resolvers = s.dns?.resolvers, !resolvers.isEmpty {
                                    ForEach(resolvers, id: \.self) { resolver in
                                        Text(resolver).font(.mono(11.5)).foregroundStyle(Theme.amber).insetRow()
                                    }
                                } else {
                                    Text("None").font(.ui(13)).foregroundStyle(Theme.text2).insetRow()
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Network drives").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                                if let mounts = s.mounts, !mounts.isEmpty {
                                    ForEach(mounts, id: \.self) { mount in
                                        Text(mount).font(.mono(11)).foregroundStyle(Theme.text2).insetRow()
                                    }
                                } else {
                                    Text("None mounted").font(.ui(13)).foregroundStyle(Theme.text2).insetRow()
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        Text("A changed DNS server or a per-domain override can send one site, often a bank, to another server.")
                            .font(.ui(12)).foregroundStyle(Theme.text3)
                    }
                }
            }
        }
    }
}

struct ConnectionRow: View {
    let connection: Connection
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 14) {
                ProgramIcon(path: connection.path, size: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(Fmt.programName(connection.path)).font(.ui(14, 600)).foregroundStyle(Theme.text)
                    PathText(connection.path, size: 10.5)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                SignatureLabel(signature: connection.signature).frame(width: 200, alignment: .leading)
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text("\(connection.remotes.count)").font(.figure(19, 600)).foregroundStyle(Theme.text)
                    Text(connection.remotes.count == 1 ? "link" : "links").font(.ui(12)).foregroundStyle(Theme.text3)
                }
                .frame(width: 70, alignment: .trailing)
                Image(systemName: "chevron.down")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Theme.text3)
                    .rotationEffect(.degrees(expanded ? 180 : 0))
            }
            if expanded {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 200), spacing: 8, alignment: .leading)],
                          alignment: .leading, spacing: 6) {
                    ForEach(connection.remotes, id: \.self) { remote in
                        Text(remote).font(.mono(11.5)).foregroundStyle(Theme.text2).lineLimit(1)
                            .textSelection(.enabled)
                    }
                }
                .padding(14)
                .background(RoundedRectangle(cornerRadius: Theme.corner(12), style: .continuous).fill(Theme.well))
                .padding(.leading, 46)
            }
        }
        .insetRow()
        .onTapGesture { withAnimation(.spring(response: 0.3, dampingFraction: 0.85)) { expanded.toggle() } }
    }
}

struct ListenerRow: View {
    let listener: Listener

    var body: some View {
        HStack(spacing: 14) {
            Text("\(listener.port)").font(.figure(19, 600)).foregroundStyle(Theme.text)
                .frame(width: 66, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(listener.process).font(.ui(13, 500)).foregroundStyle(Theme.text).lineLimit(1)
                    if !listener.known { Pill("New", color: Theme.accentText, fill: Theme.accent.opacity(0.14)) }
                }
                Text(listener.address).font(.mono(10.5)).foregroundStyle(Theme.text3).lineLimit(1)
            }
            Spacer(minLength: 6)
            Pill(listener.exposed ? "Network" : "This Mac",
                 color: listener.exposed ? Theme.amber : Theme.green,
                 fill: (listener.exposed ? Theme.amber : Theme.green).opacity(0.13))
        }
        .insetRow()
        .help(listener.exposed
              ? "Other devices on your network can try to connect to this port."
              : "Only programs on this Mac can connect to this port.")
    }
}
