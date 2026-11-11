import AppKit
import SwiftUI

struct ProtectionView: View {
    @Environment(AppStore.self) private var store
    @State private var askCheck: PostureCheck?

    var body: some View {
        let checks = store.checks.sorted {
            ($0.failed ? 0 : $0.passed ? 2 : 1, -$0.severity.rank) < ($1.failed ? 0 : $1.passed ? 2 : 1, -$1.severity.rank)
        }
        let passed = store.checks.filter(\.passed).count
        let allOn = store.failingChecks.isEmpty
        let filled = Theme.skin.heroFilled
        let fill = allOn ? ThreatLevel.secure.hero : (filled ? Theme.warnFill : Theme.amber)
        let ink = filled ? (allOn ? ThreatLevel.secure.heroInk : Theme.warnInk) : Theme.text
        // Plain looks: the figure and bar take the status colour; filled looks use ink on the block.
        let figure = filled ? ink : fill

        ScreenScaffold(.protection) {
            VStack(spacing: 12) {
                Tile(padding: 26, fill: fill, hero: true) {
                    HStack(alignment: .center, spacing: 36) {
                        HStack(alignment: .firstTextBaseline, spacing: 0) {
                            Text("\(passed)").font(.figure(96, 800)).tracking(-4)
                            Text("/\(store.checks.count)").font(.figure(96, 800)).tracking(-4).opacity(0.35)
                        }
                        .foregroundStyle(figure)
                        VStack(alignment: .leading, spacing: 10) {
                            Text(allOn ? "Every protection is on." : "\(store.failingChecks.count) protection\(store.failingChecks.count == 1 ? " is" : "s are") off.")
                                .font(.display(28)).foregroundStyle(ink)
                            Text(allOn
                                 ? "Safeguard will tell you if any of these is turned off later."
                                 : "They're listed first below, each with a button that opens the right page in System Settings.")
                                .font(.ui(13.5)).foregroundStyle(ink.opacity(0.75)).lineSpacing(2)
                                .fixedSize(horizontal: false, vertical: true)
                            SegmentBar(colors: checks.map { $0.passed ? figure : (filled ? ink.opacity(0.25) : Theme.line) }, height: 8)
                                .padding(.top, 6)
                        }
                    }
                }
                .fixedSize(horizontal: false, vertical: true)

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 320), spacing: 12, alignment: .top)], spacing: 12) {
                    ForEach(checks) { check in
                        CheckTile(check: check) { askCheck = check }
                    }
                }
            }
        }
        .sheet(item: $askCheck) { AdvisorCheckSheet(check: $0) }
    }
}

struct CheckTile: View {
    @Environment(AppStore.self) private var store
    let check: PostureCheck
    var onAsk: (() -> Void)? = nil

    private var statusText: String { check.passed ? "Safe" : check.failed ? "At risk" : "Unknown" }
    private var statusColor: Color { check.passed ? Theme.green : check.failed ? Theme.amber : Theme.text3 }

    var body: some View {
        let meta = CheckMeta.for(check.key)
        Tile(padding: 20) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: meta.icon)
                        .font(.system(size: 17))
                        .foregroundStyle(Theme.text)
                        .frame(width: 42, height: 42)
                        .background(RoundShape().fill(Theme.inset))
                    Spacer()
                    Pill(statusText, color: statusColor, fill: statusColor.opacity(0.14))
                }
                Text(check.name).font(.ui(15, 600)).foregroundStyle(Theme.text)
                    .help("macOS reports: \(check.detail)")
                Text(meta.why).font(.ui(13)).foregroundStyle(Theme.text2).lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
                if check.failed {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(check.fix).font(.ui(12.5, 500)).foregroundStyle(Theme.text)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 8) {
                            if let link = meta.settingsURL, let url = URL(string: link) {
                                Button("Open Settings") { NSWorkspace.shared.open(url) }
                                    .buttonStyle(LightButtonStyle(compact: true))
                            }
                            if let command = copyableCommand {
                                Button("Copy command") {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(command, forType: .string)
                                }
                                .buttonStyle(GhostButtonStyle(compact: true))
                            }
                            if store.advisor?.enabled == true, let onAsk {
                                Button("Ask Safeguard") { onAsk() }
                                    .buttonStyle(GhostButtonStyle(compact: true))
                            }
                        }
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: Theme.corner(14), style: .continuous).fill(Theme.inset))
                }
            }
        }
    }

    private var copyableCommand: String? {
        guard check.fix.contains("ssh-keygen") || check.fix.contains("sudo ") || check.fix.contains("csrutil") else { return nil }
        return check.fix.components(separatedBy: ": ").last?.components(separatedBy: "  (").first
    }
}

struct CheckMeta {
    let icon: String
    let why: String
    let settingsURL: String?

    static func `for`(_ key: String) -> CheckMeta {
        switch key {
        case "filevault":
            CheckMeta(icon: "internaldrive",
                      why: "Encrypts everything on your disk, so a lost or stolen Mac gives away nothing.",
                      settingsURL: "x-apple.systempreferences:com.apple.preference.security?FileVault")
        case "firewall":
            CheckMeta(icon: "network.badge.shield.half.filled",
                      why: "Blocks unwanted incoming connections from other machines on your network.",
                      settingsURL: "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall")
        case "stealth":
            CheckMeta(icon: "eye.slash",
                      why: "Makes your Mac ignore network probes, so scanners on public Wi-Fi can't see it.",
                      settingsURL: "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall")
        case "sip":
            CheckMeta(icon: "cpu",
                      why: "Stops anything, even malware with admin rights, from modifying core parts of macOS.",
                      settingsURL: nil)
        case "gatekeeper":
            CheckMeta(icon: "checkmark.seal",
                      why: "Blocks apps that aren't from a verified developer or have been tampered with.",
                      settingsURL: "x-apple.systempreferences:com.apple.preference.security?General")
        case "screenlock":
            CheckMeta(icon: "lock.display",
                      why: "Locks your Mac the moment it sleeps, so nobody walks up to an open session.",
                      settingsURL: "x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension")
        case "AutomaticallyInstallMacOSUpdates":
            CheckMeta(icon: "arrow.down.circle",
                      why: "Installs macOS updates, which close the holes attackers actively exploit.",
                      settingsURL: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension")
        case "CriticalUpdateInstall":
            CheckMeta(icon: "bolt.shield",
                      why: "Lets Apple push urgent security fixes and malware definitions within hours.",
                      settingsURL: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension")
        case "com.openssh.sshd":
            CheckMeta(icon: "terminal",
                      why: "Remote Login lets anyone on your network try to log in. Keep it off unless you use it.",
                      settingsURL: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")
        case "com.apple.screensharing":
            CheckMeta(icon: "display.2",
                      why: "Screen Sharing lets others view and control your screen remotely.",
                      settingsURL: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")
        case "guest":
            CheckMeta(icon: "person.crop.circle.badge.questionmark",
                      why: "A guest account gives anyone with physical access a way in without a password.",
                      settingsURL: "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension")
        case "sshkeys":
            CheckMeta(icon: "key",
                      why: "Infostealer malware copies SSH keys. A passphrase makes a stolen key useless.",
                      settingsURL: nil)
        case "updates":
            CheckMeta(icon: "arrow.triangle.2.circlepath",
                      why: "Pending updates often contain security fixes.",
                      settingsURL: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension")
        case "authenticated_root":
            CheckMeta(icon: "checkmark.shield",
                      why: "The system volume is sealed and signed, so malware cannot quietly patch macOS itself.",
                      settingsURL: nil)
        case "firmware_password":
            CheckMeta(icon: "memorychip",
                      why: "Stops someone with the Mac in hand from booting another system. Apple silicon does this itself.",
                      settingsURL: nil)
        case "autologin":
            CheckMeta(icon: "person.badge.key",
                      why: "Automatic login skips the password entirely, so a stolen Mac opens straight to your desktop.",
                      settingsURL: "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension")
        case "mdm":
            CheckMeta(icon: "building.2",
                      why: "Device management can watch your screen, install apps and read your files. Only your employer should be here.",
                      settingsURL: "x-apple.systempreferences:com.apple.preference.security?Profiles")
        case "sudo_nopasswd":
            CheckMeta(icon: "exclamationmark.shield",
                      why: "A NOPASSWD rule lets anything running as you become root without a password.",
                      settingsURL: nil)
        case "trust_user":
            CheckMeta(icon: "checkmark.seal.fill",
                      why: "A root certificate you did not install lets its owner read every encrypted site you visit.",
                      settingsURL: "x-apple.systempreferences:com.apple.preference.security?Certificates")
        case "proxy":
            CheckMeta(icon: "arrow.triangle.branch",
                      why: "A proxy or PAC file routes your traffic through someone else's server.",
                      settingsURL: "x-apple.systempreferences:com.apple.Network-Settings.extension")
        case "file_sharing":
            CheckMeta(icon: "folder.badge.person.crop",
                      why: "File sharing publishes folders on your network, where anyone can try credentials.",
                      settingsURL: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")
        case "remote_management":
            CheckMeta(icon: "display",
                      why: "Remote Management lets another machine control this Mac as if it were sitting in front of it.",
                      settingsURL: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")
        case "printer_sharing":
            CheckMeta(icon: "printer",
                      why: "Printer sharing exposes your queue and the Mac to the local network.",
                      settingsURL: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")
        case "internet_sharing":
            CheckMeta(icon: "antenna.radiowaves.left.and.right",
                      why: "Internet Sharing turns your Mac into a router that other devices can attach to.",
                      settingsURL: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")
        case "backup":
            CheckMeta(icon: "externaldrive.badge.timemachine",
                      why: "The only reliable answer to ransomware is a recent backup made before the encryption started.",
                      settingsURL: "x-apple.systempreferences:com.apple.Time-Machine-Settings.extension")
        case "xprotect":
            CheckMeta(icon: "shield.lefthalf.filled",
                      why: "XProtect is the antivirus built into macOS. If its definitions vanish, so does your last line of defence.",
                      settingsURL: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension")
        case "tcc":
            CheckMeta(icon: "eye",
                      why: "Screen Recording and Accessibility let an app watch everything you see and type. Audit that list.",
                      settingsURL: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture")
        case "airdrop":
            CheckMeta(icon: "dot.radiowaves.left.and.right",
                      why: "AirDrop open to everyone means strangers nearby can send you files with a single tap.",
                      settingsURL: "x-apple.systempreferences:com.apple.AirDrop-Handoff-Settings.extension")
        case "dns":
            CheckMeta(icon: "network",
                      why: "Whoever answers DNS decides which server your bank's name resolves to.",
                      settingsURL: "x-apple.systempreferences:com.apple.Network-Settings.extension")
        case "lockdown":
            CheckMeta(icon: "lock.circle",
                      why: "Lockdown Mode is Apple's switch for people who may be targeted personally. Most people don't need it.",
                      settingsURL: "x-apple.systempreferences:com.apple.preference.security?LockdownMode")
        default:
            CheckMeta(icon: "shield", why: "", settingsURL: nil)
        }
    }
}
