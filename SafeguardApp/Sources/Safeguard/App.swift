import AppKit
import SwiftUI
import UserNotifications

@main
struct SafeguardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var store = AppStore.shared

    var body: some Scene {
        Window("Safeguard", id: "main") {
            RootView()
                .environment(store)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1120, height: 740)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Scan") {
                Button("Scan Now") { Task { await store.scan() } }
                    .keyboardShortcut("r")
            }
        }

        MenuBarExtra(isInserted: Binding(get: { store.showInMenuBar && AppStore.snapshotDir == nil },
                                         set: { on in
                                             // Snapshot runs hide the icon; that must not turn the setting off.
                                             guard AppStore.snapshotDir == nil else { return }
                                             store.showInMenuBar = on
                                             store.persistSettings()
                                         })) {
            MenuBarPanel().environment(store)
        } label: {
            MenuBarLabel().environment(store)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Without this, macOS silently drops banners while Safeguard is the front app.
final class NotificationPresenter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationPresenter()

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler:
                                    @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .list])
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// The dashboard window, once SwiftUI has made it.
    static weak var mainWindow: NSWindow?
    /// Started at login: stay in the menu bar instead of opening the dashboard.
    static var startHidden = false

    @MainActor private var store: AppStore { AppStore.shared }

    @MainActor func applicationDidFinishLaunching(_ notification: Notification) {
        AppDelegate.startHidden = AppStore.launchedAtLogin && store.runInBackground && AppStore.snapshotDir == nil
        NSApp.setActivationPolicy(AppDelegate.startHidden ? .accessory : .regular)
        if AppStore.snapshotDir == nil {
            UNUserNotificationCenter.current().delegate = NotificationPresenter.shared
        }
        if AppStore.snapshotDir == nil && !AppDelegate.startHidden { NSApp.activate(ignoringOtherApps: true) }
        Task { await store.start() }
    }

    @MainActor func applicationWillTerminate(_ notification: Notification) {
        store.stopBrowserBridge()
    }

    @MainActor func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        AppStore.snapshotDir != nil || !store.runInBackground
    }

    /// Opening Safeguard again (Dock, Finder, Spotlight) while it runs in the background brings the window back.
    @MainActor func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { store.showMainWindow() }
        return true
    }

    /// With the window closed Safeguard lives in the menu bar only, so it leaves the Dock and app switcher.
    @MainActor static func mainWindowWillClose() {
        guard AppStore.shared.runInBackground else { return }
        DispatchQueue.main.async { NSApp.setActivationPolicy(.accessory) }
    }
}

/// Lets the hidden-title-bar window be dragged by its background, and paints it to match.
struct WindowConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            guard let window = view.window else { return }
            window.isMovableByWindowBackground = true
            window.titlebarAppearsTransparent = true
            window.backgroundColor = Theme.windowBackground
            // Always open at the default size rather than whatever macOS saved from an earlier run.
            window.isRestorable = false
            if AppStore.snapshotDir != nil {
                window.setFrame(NSRect(origin: CGPoint(x: -6000, y: -6000), size: Snapshotter.size), display: true)
            }
            guard AppDelegate.mainWindow !== window else { return }
            AppDelegate.mainWindow = window
            NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window,
                                                   queue: .main) { _ in
                MainActor.assumeIsolated { AppDelegate.mainWindowWillClose() }
            }
            if AppDelegate.startHidden {
                AppDelegate.startHidden = false
                window.close()
            }
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

struct RootView: View {
    @Environment(AppStore.self) private var store
    @Environment(\.openWindow) private var openWindow

    private var content: some View {
        ZStack {
            if store.status != nil {
                screen
            } else {
                FirstScanView()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    var body: some View {
        let skin = store.look.skin
        Group {
            switch skin.chrome {
            case .ops:
                VStack(spacing: 0) {
                    OpsHeader()
                    HStack(spacing: 0) {
                        OpsNav()
                        content
                    }
                }
            case .rail:
                HStack(spacing: 0) {
                    Rail()
                    content
                }
            case .sidebar:
                HStack(spacing: skin.gap) {
                    SideNav()
                    content
                }
                .padding(skin.outer)
            case .topbar:
                VStack(spacing: 0) {
                    TopNav()
                    content
                }
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .overlay(alignment: .bottom) { ToastView() }
        .overlay { ConfirmOverlay() }
        .background(WindowConfigurator())
        .preferredColorScheme(skin.dark ? .dark : .light)
        .frame(minWidth: skin.minWidth, minHeight: 640)
        .ignoresSafeArea()
        // Colours and fonts are read from `Theme` as views draw; a new identity redraws all of them.
        .id(store.look)
        .onAppear { store.openMainWindowAction = { openWindow(id: "main") } }
    }

    @ViewBuilder private var screen: some View {
        switch store.screen {
        case .overview: OverviewView()
        case .threats: ThreatsView()
        case .protection: ProtectionView()
        case .network: NetworkView()
        case .browser: BrowserView()
        case .startup: StartupView()
        case .links: LinkShieldView()
        case .advisor: AdvisorView()
        case .activity: ActivityView()
        case .settings: SettingsView()
        }
    }
}

// MARK: - Rail

struct Rail: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        VStack(spacing: 8) {
            BrandMark(size: 40)
                .padding(.top, 44)
                .padding(.bottom, 18)
                .help("Safeguard")
            RailButton(screen: .overview)
            RailButton(screen: .threats, badge: store.activeAlerts.isEmpty ? nil : store.level.hero)
            RailButton(screen: .protection, badge: store.failingChecks.isEmpty ? nil : Theme.amber)
            RailButton(screen: .network)
            RailButton(screen: .browser)
            RailButton(screen: .startup)
            RailButton(screen: .links)
            RailButton(screen: .advisor)
            RailButton(screen: .activity)
            Spacer()
            RailButton(screen: .settings).padding(.bottom, 20)
        }
        .frame(width: 84)
    }
}

struct RailButton: View {
    @Environment(AppStore.self) private var store
    let screen: Screen
    var badge: Color? = nil
    @State private var hover = false

    var body: some View {
        let selected = store.screen == screen
        Button {
            store.screen = screen
        } label: {
            Image(systemName: screen.icon)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(selected ? Theme.bg : hover ? Theme.text : Theme.text3)
                .frame(width: 46, height: 46)
                .background(RoundedRectangle(cornerRadius: Theme.corner(15), style: .continuous)
                    .fill(selected ? Theme.text : hover ? Theme.tile : .clear))
                .overlay(alignment: .topTrailing) {
                    if let badge {
                        Circle().fill(badge).frame(width: 9, height: 9)
                            .overlay(Circle().strokeBorder(Theme.bg, lineWidth: 2))
                            .offset(x: -9, y: 9)
                    }
                }
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .help(screen.title)
        .accessibilityLabel(screen.title)
    }
}

// MARK: - Screen scaffold

struct ScreenScaffold<Content: View, Accessory: View>: View {
    @Environment(AppStore.self) private var store
    let screen: Screen
    var scrolls: Bool
    let accessory: Accessory
    let content: Content

    init(_ screen: Screen, scrolls: Bool = true,
         @ViewBuilder accessory: () -> Accessory,
         @ViewBuilder content: () -> Content) {
        self.screen = screen
        self.scrolls = scrolls
        self.accessory = accessory()
        self.content = content()
    }

    private var eyebrow: String {
        guard screen == .overview else { return screen.subtitle }
        let hour = Calendar.current.component(.hour, from: .now)
        let part = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening"
        let first = store.status?.user.split(separator: " ").first.map(String.init) ?? ""
        return first.isEmpty ? part : "\(part), \(first)"
    }

    private var title: String { screen == .overview ? "Here’s your Mac today" : screen.title }

    var body: some View {
        switch Theme.look {
        case .fieldops: opsBody
        case .bento: bentoBody
        default: designBody
        }
    }

    /// Field Ops: the header bar already carries scan controls, so a page gets a one-line title.
    private var opsBody: some View {
        VStack(spacing: 0) {
            if screen != .overview {
                HStack(alignment: .firstTextBaseline, spacing: 14) {
                    Text("// \(screen.title)").font(.ui(17, 700)).labelCase(tracking: 1).foregroundStyle(Theme.accent)
                    Text(screen.subtitle).font(.ui(13)).foregroundStyle(Theme.text3).lineLimit(1)
                    Spacer(minLength: 8)
                    accessory
                }
                .padding(.horizontal, 26)
                .padding(.top, 20)
            }

            if let error = store.errorMessage {
                ErrorBanner(message: error).padding(.horizontal, 26).padding(.top, 14)
            }

            if scrolls {
                ScrollView {
                    content.padding(.horizontal, 26).padding(.vertical, 20)
                }
                .scrollIndicators(.never)
            } else {
                content.padding(.horizontal, 26).padding(.vertical, 20)
            }
        }
    }

    /// Graphite, Dot Matrix, Swiss, Hardware and Neo-Brutal: a header row, then the page.
    private var designBody: some View {
        let s = Theme.skin
        return VStack(spacing: 0) {
            designHeader
            if let error = store.errorMessage {
                ErrorBanner(message: error).padding(.leading, s.padLead).padding(.trailing, s.padTrail).padding(.bottom, 14)
            }
            if scrolls {
                ScrollView {
                    content.padding(.leading, s.padLead).padding(.trailing, s.padTrail).padding(.bottom, s.padBottom)
                        .padding(.top, 2)
                }
                .scrollIndicators(.never)
            } else {
                content.padding(.leading, s.padLead).padding(.trailing, s.padTrail).padding(.bottom, s.padBottom)
            }
        }
    }

    private var designHeader: some View {
        let s = Theme.skin
        let top = s.outer > 0 ? 4 : s.padTop
        return Group {
            if Theme.look == .swiss {
                let n = (Screen.allCases.firstIndex(of: screen) ?? 0) + 1
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    Text("\(String(format: "%02d", n)) — \(screen.title)").font(.ui(13, 600)).foregroundStyle(Theme.text)
                    Spacer()
                    Text(Date.now.formatted(.dateTime.weekday(.wide).day().month(.wide)))
                        .font(.ui(12.5)).foregroundStyle(Theme.text3)
                    accessory
                    Button { Task { await store.scan() } } label: { Text(store.scanning ? "Scanning…" : "Scan now →") }
                        .buttonStyle(LightButtonStyle()).disabled(store.scanning)
                }
                .padding(.bottom, 14)
                .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
                .padding(.bottom, 4)
            } else {
                HStack(alignment: .center, spacing: 14) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(screen.title).font(.display(26)).foregroundStyle(Theme.text)
                        Text(screen == .overview ? store.hostLine : screen.subtitle)
                            .font(.ui(13)).foregroundStyle(Theme.text3).lineLimit(1)
                    }
                    Spacer(minLength: 8)
                    accessory
                    ScanControl()
                }
                .padding(.bottom, 14)
            }
        }
        .padding(.leading, s.padLead)
        .padding(.trailing, s.padTrail)
        .padding(.top, top)
        .padding(.bottom, 8)
    }

    private var bentoBody: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 14) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(eyebrow).font(.ui(13)).foregroundStyle(Theme.text2)
                    Text(title).font(.display(30)).foregroundStyle(Theme.text)
                }
                Spacer()
                accessory
                ScanControl()
            }
            .padding(.leading, 8)
            .padding(.trailing, 32)
            .padding(.top, 40)
            .padding(.bottom, 20)

            if let error = store.errorMessage {
                ErrorBanner(message: error).padding(.leading, 8).padding(.trailing, 32).padding(.bottom, 14)
            }

            if scrolls {
                ScrollView {
                    content.padding(.leading, 8).padding(.trailing, 32).padding(.bottom, 28)
                }
                .scrollIndicators(.never)
            } else {
                content.padding(.leading, 8).padding(.trailing, 32).padding(.bottom, 24)
            }
        }
    }
}

extension ScreenScaffold where Accessory == EmptyView {
    init(_ screen: Screen, scrolls: Bool = true, @ViewBuilder content: () -> Content) {
        self.init(screen, scrolls: scrolls, accessory: { EmptyView() }, content: content)
    }
}

struct ScanControl: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        HStack(spacing: 14) {
            TimelineView(.periodic(from: .now, by: 30)) { _ in
                Text(store.scanning ? "Scanning…" : "Scanned \(Fmt.relative(store.lastScanDate))")
                    .font(.ui(12.5)).foregroundStyle(Theme.text2)
            }
            Button {
                Task { await store.scan() }
            } label: {
                HStack(spacing: 7) {
                    if store.scanning { Spinner(color: ButtonSpec.make(.primary).ink, size: 11) }
                    Text(store.scanning ? "Scanning" : "Scan now")
                }
            }
            .buttonStyle(LightButtonStyle())
            .disabled(store.scanning)
        }
    }
}

struct ErrorBanner: View {
    @Environment(AppStore.self) private var store
    let message: String

    var body: some View {
        HStack(spacing: 12) {
            Dot(color: Theme.red)
            Text(message).font(.ui(13)).foregroundStyle(Theme.text).lineLimit(2)
            Spacer()
            Button("Dismiss") { store.errorMessage = nil }.buttonStyle(GhostButtonStyle(compact: true))
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(PanelSurface(radius: 16, fill: Theme.tile))
    }
}

struct FirstScanView: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        VStack(spacing: 16) {
            BrandMark(size: 56)
            if let error = store.errorMessage {
                Text("Safeguard couldn’t start").font(.display(26)).foregroundStyle(Theme.text)
                Text(error).font(.ui(13)).foregroundStyle(Theme.text2).multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
                Button("Try again") { Task { await store.scan() } }.buttonStyle(LightButtonStyle())
            } else {
                Text("Running your first scan").font(.display(26)).foregroundStyle(Theme.text)
                HStack(spacing: 8) {
                    Spinner(size: 12)
                    Text("Checking settings, startup items, open ports and live connections.")
                        .font(.ui(13)).foregroundStyle(Theme.text2)
                }
            }
        }
    }
}

// MARK: - Overlays

struct ToastView: View {
    @Environment(AppStore.self) private var store

    var body: some View {
        if let toast = store.toast {
            Text(toast)
                .font(.ui(13, 500))
                .foregroundStyle(Theme.ops ? Theme.accentInk : Theme.bg)
                .padding(.horizontal, 18)
                .padding(.vertical, 11)
                .background(PillShape().fill(Theme.ops ? Theme.accent : Theme.text))
                .overlay(PillShape().strokeBorder(Theme.skin.panelShadow > 0 ? Color(hex: 0x111111) : .clear, lineWidth: 2))
                .padding(.bottom, 26)
                .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }
}

struct ConfirmOverlay: View {
    @Environment(AppStore.self) private var store
    @State private var working = false

    var body: some View {
        if let request = store.confirm {
            ZStack {
                Color.black.opacity(0.55).ignoresSafeArea()
                    .onTapGesture { if !working { store.confirm = nil } }
                VStack(alignment: .leading, spacing: 12) {
                    Text(request.title).font(.display(24)).foregroundStyle(Theme.text)
                    Text(request.message).font(.ui(13.5)).foregroundStyle(Theme.text2).lineSpacing(3)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 8) {
                        Spacer()
                        Button("Cancel") { store.confirm = nil }
                            .buttonStyle(GhostButtonStyle())
                            .keyboardShortcut(.cancelAction)
                        Button {
                            working = true
                            Task {
                                await request.perform()
                                working = false
                                store.confirm = nil
                            }
                        } label: {
                            HStack(spacing: 6) {
                                if working { Spinner(color: Theme.bg, size: 10) }
                                Text(request.action)
                            }
                        }
                        .buttonStyle(LightButtonStyle())
                        .keyboardShortcut(.defaultAction)
                        .disabled(working)
                    }
                    .padding(.top, 10)
                }
                .padding(26)
                .frame(width: 460)
                .background(PanelSurface(radius: 26, fill: Theme.tile))
            }
            .transition(.opacity)
        }
    }
}

// MARK: - Snapshots (for reviewing the design without a screen recording permission)

@MainActor
enum Snapshotter {
    /// `--switch-to bento|fieldops` flips the look mid-run to test the live switch.
    static let switchTo: Look? = {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--switch-to"), i + 1 < args.count else { return nil }
        return Look(rawValue: args[i + 1])
    }()

    /// `--size WxH` picks the window size for snapshots (default 1380x900).
    static let size: CGSize = {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--size"), i + 1 < args.count else { return CGSize(width: 1380, height: 900) }
        let parts = args[i + 1].split(separator: "x").compactMap { Double($0) }
        return parts.count == 2 ? CGSize(width: parts[0], height: parts[1]) : CGSize(width: 1380, height: 900)
    }()

    static func run(store: AppStore, dir: URL) async {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        await store.checkURL("http://paypal.com.secure-login.xyz/verify-account")
        for (i, screen) in Screen.allCases.enumerated() {
            store.screen = screen
            if screen == .threats { store.selectedAlertID = store.activeAlerts.first?.id }
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            capture(to: dir.appendingPathComponent("\(i + 1)-\(screen.rawValue).png"))
        }
        if let other = switchTo {
            store.setLook(other)
            for screen in [Screen.overview, .settings] {
                store.screen = screen
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                capture(to: dir.appendingPathComponent("10-switched-\(screen.rawValue).png"))
            }
        }
        // The menu bar panel, hosted in an off-screen window of its own.
        let panel = NSWindow(contentRect: NSRect(x: -6000, y: -6000, width: 360, height: 600),
                             styleMask: .borderless, backing: .buffered, defer: false)
        let host = NSHostingView(rootView: MenuBarPanel().environment(store))
        panel.contentView = host
        panel.setContentSize(host.fittingSize)
        panel.orderFront(nil)
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        capture(host, to: dir.appendingPathComponent("9-menubar.png"))
        NSApp.terminate(nil)
    }

    private static func capture(to url: URL) {
        guard let view = AppDelegate.mainWindow?.contentView else { return }
        capture(view, to: url)
    }

    private static func capture(_ view: NSView, to url: URL) {
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
    }
}
