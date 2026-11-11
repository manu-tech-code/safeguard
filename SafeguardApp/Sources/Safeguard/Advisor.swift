import Foundation
import Security
import SwiftUI

// MARK: - Models returned by the engine

struct AdvisorProviderHint: Codable, Hashable {
    let baseUrl: String
    let model: String
    let note: String
}

struct AdvisorStatus: Codable, Hashable {
    var enabled: Bool
    var provider: String
    var baseUrl: String
    var model: String
    var maxTokens: Int
    var dailyCap: Int
    var sendDetails: Bool
    var explainOnly: Bool
    var keyPresent: Bool
    var callsToday: Int
    var autoDigest: Bool?
    var reasoningEffort: String?
    var efforts: [String]?
    var providers: [String: AdvisorProviderHint]?
}

struct AgentModel: Codable, Identifiable, Hashable {
    let id: String
    let label: String
}

struct AgentModels: Codable, Hashable {
    var ok: Bool
    var error: String?
    var models: [AgentModel]?
    var cached: Bool?
}

struct AgentStep: Codable, Hashable, Identifiable {
    var title: String
    var detail: String?
    var ok: Bool?
    var id: String { title + "|" + (detail ?? "") }
}

struct AdvisorProposal: Codable, Hashable {
    var ok: Bool
    var error: String?
    var explanation: String?
    var actionId: String?
    var title: String?
    var why: String?
    var risk: String?
    var needsAdmin: Bool?
    var params: [String: String]?
    var command: String?
    var confidence: Double?
    var model: String?
    var provider: String?
    var candidates: [String]?
    var rejected: String?
    var steps: [AgentStep]?
}

struct FixRecord: Codable, Hashable, Identifiable {
    let id: String
    var at: String?
    let action: String
    let title: String
    var verified: Bool?
    var commands: [String]?
    var quarantine: String?
    var rolledBack: Bool?
    var undone: Bool?
}

struct FixOutcome: Codable, Hashable {
    var ok: Bool
    var error: String?
    var message: String?
    var record: FixRecord?
}

struct AdvisorTestResult: Codable, Hashable {
    var ok: Bool
    var error: String?
    var model: String?
    var provider: String?
}

struct DigestPoint: Codable, Hashable {
    var finding: String
    var why: String
    var next: String
}

struct AdvisorDigest: Codable, Hashable {
    var ok: Bool
    var error: String?
    var summary: String?
    var priorities: [DigestPoint]?
    var model: String?
    var generatedAt: String?
}

struct AdvisorAnswer: Codable, Hashable {
    var ok: Bool
    var error: String?
    var answer: String?
}

struct LoginItemsResult: Codable, Hashable {
    var ok: Bool
    var error: String?
    var checkedAt: String?
    var items: [HiddenLoginItem]?
}

struct AdvisorExchange: Identifiable, Hashable {
    let id = UUID()
    let question: String
    let answer: String
}

// MARK: - Key file

enum AdvisorKeychain {
    static let service = "local.safeguard.agent"
    /// Read once per app session: one unlock dialog, then memory.
    private static var cache: [String: String] = [:]

    static func save(_ value: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        var item = query
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { return false }
        cache[account] = value
        return true
    }

    private static func readItem(_ account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func load(account: String) -> String? {
        if let value = cache[account] { return value }
        guard let value = readItem(account) else { return nil }
        cache[account] = value
        return value
    }

    /// Attributes only: this does not decrypt the secret, so it should not prompt.
    static func exists(account: String) -> Bool {
        if cache[account] != nil { return true }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess
    }

    static func delete(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        cache.removeValue(forKey: account)
    }
}

// MARK: - Store

extension AppStore {
    static func base64JSON(_ object: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return data.base64EncodedString()
    }

    /// The key travels to the engine in the environment, never in argv or on disk.
    /// Config reads pass an empty value so they never trigger a Keychain prompt.
    func advisorEnvironment(includeKey: Bool = true) -> [String: String] {
        let provider = advisor?.provider ?? "openai"
        let value = includeKey ? (AdvisorKeychain.load(account: provider) ?? "") : ""
        return ["SAFEGUARD_AGENT_KEY": value]
    }

    private func applyLocalKeyPresence(_ status: AdvisorStatus?) -> AdvisorStatus? {
        guard var status else { return nil }
        status.keyPresent = status.provider == "local" || AdvisorKeychain.exists(account: status.provider)
        return status
    }

    func refreshAdvisor() async {
        let fetched = try? await Engine.call(AdvisorStatus.self, ["agent-config"],
                                             environment: advisorEnvironment(includeKey: false))
        advisor = applyLocalKeyPresence(fetched)
    }

    func saveAdvisor(_ fields: [String: Any], silent: Bool = false) async {
        guard let encoded = AppStore.base64JSON(fields) else { return }
        do {
            let saved = try await Engine.call(AdvisorStatus.self, ["agent-save", encoded],
                                              environment: advisorEnvironment(includeKey: false))
            advisor = applyLocalKeyPresence(saved)
            if !silent { show("Advisor settings saved") }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func setAdvisorEnabled(_ on: Bool) async {
        await saveAdvisor(["enabled": on])
    }

    func loadModels(force: Bool = false) async {
        modelsLoading = true
        defer { modelsLoading = false }
        do {
            let result = try await Engine.call(AgentModels.self,
                                               ["agent-models"] + (force ? ["refresh"] : []),
                                               environment: advisorEnvironment())
            if result.ok {
                agentModels = result.models ?? []
                modelError = nil
            } else {
                modelError = result.error ?? "Could not list models"
            }
        } catch {
            modelError = error.localizedDescription
        }
    }

    func setModel(_ id: String) async {
        await saveAdvisor(["model": id])
    }

    func setEffort(_ effort: String) async {
        await saveAdvisor(["reasoning_effort": effort])
    }

    func setProvider(_ provider: String) async {
        guard let hint = advisor?.providers?[provider] else {
            await saveAdvisor(["provider": provider])
            return
        }
        await saveAdvisor(["provider": provider, "base_url": hint.baseUrl, "model": hint.model])
    }

    func saveAdvisorKey(_ key: String) async {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let provider = advisor?.provider else { return }
        if AdvisorKeychain.save(trimmed, account: provider) {
            await refreshAdvisor()
            await loadModels(force: true)
            show("Key saved in your login Keychain")
        } else {
            errorMessage = "Could not save the key to Keychain."
        }
    }

    func removeAdvisorKey() async {
        guard let provider = advisor?.provider else { return }
        AdvisorKeychain.delete(account: provider)
        await refreshAdvisor()
        show("Key removed")
    }

    func testAdvisor() async -> String {
        do {
            let result = try await Engine.call(AdvisorTestResult.self, ["agent-test"],
                                               environment: advisorEnvironment())
            await refreshAdvisor()
            return result.ok ? "Connected to \(result.model ?? "the model")" : (result.error ?? "Failed")
        } catch {
            return error.localizedDescription
        }
    }

    // MARK: contexts

    private func alertContext(_ alert: ThreatAlert) -> [String: Any] {
        var context: [String: Any] = ["alert": [
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity.rawValue,
            "detail": alert.detail,
            "advice": alert.advice,
        ]]
        if let path = alert.subjectPath { context["path"] = path }
        return context
    }

    private func checkContext(_ check: PostureCheck) -> [String: Any] {
        ["check": ["key": check.key, "name": check.name, "status": check.status,
                   "severity": check.severity.rawValue, "detail": check.detail, "fix": check.fix]]
    }

    func askAdvisor(_ alert: ThreatAlert) async {
        guard advisor?.enabled == true else {
            show("Turn on the advisor in Settings first")
            return
        }
        advisorBusy = true
        advisorProposal = nil
        advisorAlertID = alert.id
        advisorCheckKey = nil
        advisorRequestKey = nil
        followups = []
        lastFix = nil
        lastFixAlertID = nil
        defer { advisorBusy = false }

        guard let encoded = AppStore.base64JSON(alertContext(alert)) else { return }
        do {
            let proposal = try await Engine.call(AdvisorProposal.self, ["agent-propose", encoded],
                                                 environment: advisorEnvironment())
            advisorProposal = proposal
            if !proposal.ok { show(proposal.error ?? "The advisor could not answer") }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func askRequest(_ request: BrowserRequest) async {
        guard advisor?.enabled == true else {
            show("Turn on the advisor in Settings first")
            return
        }
        advisorBusy = true
        advisorProposal = nil
        advisorRequestKey = request.id
        advisorAlertID = nil
        advisorCheckKey = nil
        followups = []
        lastFix = nil
        lastFixAlertID = nil
        defer { advisorBusy = false }
        let context: [String: Any] = ["request": [
            "id": request.id, "domain": request.domain, "url": request.url,
            "type": request.type, "method": request.method,
            "action": request.action, "reason": request.reason ?? "",
        ]]
        guard let encoded = AppStore.base64JSON(context) else { return }
        do {
            let proposal = try await Engine.call(AdvisorProposal.self, ["agent-propose", encoded],
                                                 environment: advisorEnvironment())
            advisorProposal = proposal
            if !proposal.ok { show(proposal.error ?? "The advisor could not answer") }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func askCheck(_ check: PostureCheck) async {
        guard advisor?.enabled == true else {
            show("Turn on the advisor in Settings first")
            return
        }
        advisorBusy = true
        advisorProposal = nil
        advisorCheckKey = check.key
        advisorRequestKey = nil
        advisorAlertID = nil
        followups = []
        lastFix = nil
        lastFixAlertID = nil
        defer { advisorBusy = false }

        guard let encoded = AppStore.base64JSON(checkContext(check)) else { return }
        do {
            let proposal = try await Engine.call(AdvisorProposal.self, ["agent-propose", encoded],
                                                 environment: advisorEnvironment())
            advisorProposal = proposal
            if !proposal.ok { show(proposal.error ?? "The advisor could not answer") }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func askFollowup(_ question: String, alert: ThreatAlert? = nil, check: PostureCheck? = nil) async {
        let trimmed = question.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var request: [String: Any] = ["question": trimmed, "history": followups.flatMap {
            [["role": "user", "content": $0.question],
             ["role": "assistant", "content": $0.answer]]
        }]
        if let alert {
            request["alert"] = alertContext(alert)["alert"]
            if let path = alert.subjectPath { request["path"] = path }
        } else if let check {
            request["check"] = checkContext(check)["check"]
        }
        followupBusy = true
        defer { followupBusy = false }
        guard let encoded = AppStore.base64JSON(request) else { return }
        do {
            let answer = try await Engine.call(AdvisorAnswer.self, ["agent-followup", encoded],
                                               environment: advisorEnvironment())
            if answer.ok, let text = answer.answer {
                followups.append(AdvisorExchange(question: trimmed, answer: text))
            } else {
                show(answer.error ?? "No answer")
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: digest

    func askDigest(silent: Bool = false) async {
        guard advisor?.enabled == true else {
            if !silent { show("Turn on the advisor in Settings first") }
            return
        }
        digestBusy = true
        defer { digestBusy = false }
        do {
            let digest = try await Engine.call(AdvisorDigest.self, ["agent-digest"],
                                               environment: advisorEnvironment())
            if digest.ok {
                advisorDigest = digest
                UserDefaults.standard.set(Date(), forKey: "advisorDigestAt")
            } else if !silent {
                show(digest.error ?? "Could not brief this scan")
            }
        } catch {
            if !silent { errorMessage = error.localizedDescription }
        }
    }

    func autoDigestIfDue() async {
        guard advisor?.autoDigest == true else { return }
        if let last = UserDefaults.standard.object(forKey: "advisorDigestAt") as? Date,
           Date().timeIntervalSince(last) < 20 * 3600 { return }
        await askDigest(silent: true)
    }

    // MARK: fixes

    func applyProposal(_ proposal: AdvisorProposal) async {
        guard let action = proposal.actionId else { return }
        fixing = true
        defer { fixing = false }
        guard let encoded = AppStore.base64JSON(proposal.params ?? [:]) else { return }
        do {
            let outcome = try await Engine.call(FixOutcome.self, ["fix-apply", action, encoded])
            lastFixAlertID = advisorAlertID ?? advisorCheckKey ?? advisorRequestKey
            lastFix = outcome
            if outcome.ok {
                advisorProposal = nil
                show(outcome.message ?? "Fixed")
                await scan()
                await loadFixRecords()
                if screen == .browser { await loadBrowser() }
            } else {
                show(outcome.error ?? "Could not apply the fix")
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func undoFix(_ recordID: String) async {
        fixing = true
        defer { fixing = false }
        do {
            let outcome = try await Engine.call(FixOutcome.self, ["fix-undo", recordID])
            if outcome.ok {
                lastFix = nil
                show(outcome.message ?? "Undone")
                await scan()
                await loadFixRecords()
            } else {
                show(outcome.error ?? "Could not undo")
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func loadBrowser(silent: Bool = false, refreshVisits: Bool = false) async {
        if !silent { browserLoading = true }
        defer { if !silent { browserLoading = false } }
        guard let encoded = AppStore.base64JSON(["days": browserDays, "query": browserQuery,
                                                 "limit": 400, "refresh": refreshVisits]) else { return }
        if let overview = try? await Engine.call(BrowserOverview.self, ["browser-overview", encoded]) {
            browser = overview
            browserUpdatedAt = Date()
        }
    }

    func importBrowserNow() async {
        browserLoading = true
        defer { browserLoading = false }
        _ = try? await Engine.call(BrowserSyncResult.self, ["browser-sync"])
        await loadBrowser()
    }

    func saveBrowserRules(block: [String], warn: [String]) async {
        guard let encoded = AppStore.base64JSON(["block": block, "warn": warn]) else { return }
        _ = try? await Engine.call(BrowserRules.self, ["browser-rules-save", encoded])
        await loadBrowser()
        show("Browser rules saved")
    }

    func installBrowserExtension() async {
        guard let result = try? await Engine.call(BrowserExtension.self, ["browser-extension"]),
              let path = result.path else {
            show("Could not write the extension")
            return
        }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(path, forType: .string)
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = ["-a", "Google Chrome", "chrome://extensions"]
        try? p.run()
        show("Path copied. In Chrome: Developer mode → Load unpacked → ⌘⇧G, ⌘V, Return")
    }

    func copyBrowserExtensionPath() {
        let path = browser?.extensionPath ?? (NSHomeDirectory() as NSString)
            .appendingPathComponent("Desktop/Safeguard Browser Extension")
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(path, forType: .string)
        show("Extension path copied")
    }

    func sweepBrowser() async -> Bool {
        guard advisor?.enabled == true else {
            show("Turn on the advisor in Settings first")
            return false
        }
        sweepBusy = true
        defer { sweepBusy = false }
        do {
            let result = try await Engine.call(BrowserSweep.self, ["browser-sweep"],
                                               environment: advisorEnvironment())
            browserSweep = result
            if !result.ok {
                show(result.error ?? "The sweep failed")
                return false
            }
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func applyBrowserRule(domain: String, action: String) async {
        guard action == "block" || action == "warn",
              let encoded = AppStore.base64JSON(["domain": domain]) else { return }
        fixing = true
        defer { fixing = false }
        do {
            let outcome = try await Engine.call(FixOutcome.self, ["fix-apply", action, encoded])
            if outcome.ok {
                show(outcome.message ?? "Rule added")
                if var sweep = browserSweep {
                    sweep.sites?.removeAll { $0.domain == domain }
                    browserSweep = sweep
                }
                await loadBrowser()
                await loadFixRecords()
            } else {
                show(outcome.error ?? "Could not add the rule")
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func startBrowserBridge() {
        guard AppStore.snapshotDir == nil, bridgeProcess == nil,
              let script = Engine.scriptPath else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: Engine.python)
        process.arguments = ["-I", script, "bridge"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        process.environment = ProcessInfo.processInfo.environment
        do {
            try process.run()
            bridgeProcess = process
        } catch {
            bridgeProcess = nil
        }
    }

    func stopBrowserBridge() {
        bridgeProcess?.terminate()
        bridgeProcess = nil
    }

    func saveBrowserRequestRetention(_ days: Int) async {
        guard let encoded = AppStore.base64JSON(["request_retention_days": days]) else { return }
        _ = try? await Engine.call(BrowserConfig.self, ["browser-save", encoded])
        await loadBrowser()
    }

    func saveBrowserRetention(_ days: Int) async {
        guard let encoded = AppStore.base64JSON(["retention_days": days]) else { return }
        _ = try? await Engine.call(BrowserConfig.self, ["browser-save", encoded])
        await loadBrowser()
    }

    func clearBrowserHistory() async {
        _ = try? await Engine.call(BrowserSyncResult.self, ["browser-clear"])
        await loadBrowser()
        show("Safeguard's browsing history cleared")
    }

    func checkLoginItems() async {
        loginItemsBusy = true
        defer { loginItemsBusy = false }
        do {
            let result = try await Engine.call(LoginItemsResult.self, ["btm-items"])
            guard result.ok else {
                errorMessage = result.error ?? "Could not read login items"
                return
            }
            status?.backgroundItems = result.items ?? []
            status?.loginItemsChecked = result.checkedAt
            let fresh = (result.items ?? []).filter { !$0.known && $0.enabled }.count
            show(fresh > 0 ? "\(fresh) new hidden login item\(fresh == 1 ? "" : "s")"
                           : "No new hidden login items")
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func loadFixRecords() async {
        fixRecords = (try? await Engine.call([FixRecord].self, ["fix-records"])) ?? []
    }

    func dismissProposal() {
        advisorProposal = nil
        advisorAlertID = nil
        advisorCheckKey = nil
        advisorRequestKey = nil
    }
}

extension View {
    /// Shared field chrome for the advisor settings.
    func advisorField(width: CGFloat? = nil) -> some View {
        self
            .textFieldStyle(.plain)
            .font(.mono(12.5))
            .foregroundStyle(Theme.text)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: Theme.corner(9), style: .continuous)
                .fill(Theme.inset))
            .frame(width: width)
    }
}

// MARK: - Settings

struct AdvisorSettings: View {
    @Environment(AppStore.self) private var store

    @State private var key = ""
    @State private var baseURL = ""
    @State private var testMessage: String?
    @State private var testing = false
    @State private var loaded = false

    private var status: AdvisorStatus? { store.advisor }
    private var isLocal: Bool { status?.provider == "local" }

    var body: some View {
        SettingsTile(icon: "sparkles",
                     title: "Advisor",
                     caption: "An optional agent that investigates a finding with read-only checks, then proposes a fix you approve.") {
            SettingRow(title: "Enable the advisor",
                       detail: "Off by default. A finding is only sent when you press Ask.") {
                Toggle("", isOn: Binding(get: { status?.enabled ?? false },
                                         set: { on in Task { await store.setAdvisorEnabled(on) } }))
                    .toggleStyle(SwitchStyle()).labelsHidden()
            }

            SettingRow(title: "Provider", detail: "Cloud APIs, or a local model that sends nothing off this Mac") {
                Segmented(options: [("openai", "OpenAI-compatible"),
                                    ("anthropic", "Anthropic"),
                                    ("local", "Local")],
                          selection: Binding(get: { status?.provider ?? "openai" },
                                             set: { p in Task { await store.setProvider(p) } }))
                    .disabled(status?.enabled != true)
            }

            SettingRow(title: "Endpoint", detail: isLocal
                           ? "Ollama or LM Studio, e.g. http://127.0.0.1:11434/v1"
                           : "Base URL, e.g. https://api.deepseek.com/v1") {
                TextField("", text: $baseURL, prompt: Text("https://").foregroundStyle(Theme.text3))
                    .advisorField(width: 280)
                    .onSubmit { save(["base_url": baseURL]) }
            }

            SettingRow(title: "Model", detail: store.modelError ?? "Fetched live from \(status?.provider ?? "the provider")") {
                HStack(spacing: 8) {
                    Menu {
                        if store.agentModels.isEmpty {
                            Text("No models listed yet")
                        }
                        ForEach(store.agentModels) { item in
                            Button {
                                Task { await store.setModel(item.id) }
                            } label: {
                                Text(item.label)
                            }
                        }
                        Divider()
                        Button("Refresh from provider") {
                            Task { await store.loadModels(force: true) }
                        }
                    } label: {
                        HStack(spacing: 8) {
                            Text(status?.model ?? "Choose a model")
                                .font(.mono(12.5)).foregroundStyle(Theme.text)
                            Image(systemName: "chevron.down")
                                .font(.system(size: 9, weight: .semibold))
                                .foregroundStyle(Theme.text3)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(RoundedRectangle(cornerRadius: Theme.corner(9), style: .continuous)
                            .fill(Theme.inset))
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                    if store.modelsLoading { Spinner(color: Theme.text2, size: 9) }
                }
            }

            SettingRow(title: "Reasoning effort",
                       detail: "Higher effort thinks longer and costs more. Off uses the provider default; some providers ignore it.") {
                Segmented(options: [("", "Off"), ("low", "Low"), ("medium", "Medium"), ("high", "High")],
                          selection: Binding(get: { status?.reasoningEffort ?? "" },
                                             set: { effort in Task { await store.setEffort(effort) } }))
            }

            SettingRow(title: "API key",
                       detail: isLocal
                           ? "Not needed for a local model."
                           : (status?.keyPresent == true
                               ? "Saved in your login Keychain (local.safeguard.agent)"
                               : "Not set. Stored in your Keychain, never in a file.")) {
                if isLocal {
                    Text("A local model needs no key.")
                        .font(.ui(12.5)).foregroundStyle(Theme.text3)
                } else {
                    HStack(spacing: 8) {
                        SecureField("", text: $key,
                                    prompt: Text(status?.keyPresent == true ? "••••••••" : "sk-…")
                                        .foregroundStyle(Theme.text3))
                            .advisorField(width: 200)
                        Button("Save") {
                            Task {
                                await store.saveAdvisorKey(key)
                                key = ""
                            }
                        }
                        .buttonStyle(GhostButtonStyle(compact: true))
                        .disabled(key.trimmingCharacters(in: .whitespaces).isEmpty)
                        if status?.keyPresent == true {
                            Button("Remove") { Task { await store.removeAdvisorKey() } }
                                .buttonStyle(TextLinkStyle(color: Theme.text3))
                        }
                    }
                }
            }

            SettingRow(title: "Explain only",
                       detail: "Never propose an action; just tell me what is going on") {
                Toggle("", isOn: Binding(get: { status?.explainOnly ?? false },
                                         set: { on in Task { await store.saveAdvisor(["explain_only": on]) } }))
                    .toggleStyle(SwitchStyle()).labelsHidden()
            }

            SettingRow(title: "Send finding details",
                       detail: "Include the evidence lines. Off sends only the title and severity.") {
                Toggle("", isOn: Binding(get: { status?.sendDetails ?? true },
                                         set: { on in Task { await store.saveAdvisor(["send_details": on]) } }))
                    .toggleStyle(SwitchStyle()).labelsHidden()
            }

            SettingRow(title: "Brief me after scans",
                       detail: "Once a day, summarise findings without asking. Sends the same data, automatically.") {
                Toggle("", isOn: Binding(get: {
                    UserDefaults.standard.bool(forKey: "advisorAutoDigest")
                }, set: { on in
                    UserDefaults.standard.set(on, forKey: "advisorAutoDigest")
                    Task { await store.saveAdvisor(["auto_digest": on]) }
                }))
                .toggleStyle(SwitchStyle()).labelsHidden()
            }

            SettingRow(title: "Daily request limit", detail: "\(status?.callsToday ?? 0) used today") {
                Segmented(options: [(10, "10"), (20, "20"), (40, "40"), (100, "100")],
                          selection: Binding(get: { status?.dailyCap ?? 40 },
                                             set: { cap in Task { await store.saveAdvisor(["daily_cap": cap]) } }))
            }

            SettingRow(title: "Connection", detail: testMessage ?? "Check the key and endpoint") {
                HStack(spacing: 8) {
                    if testing { Spinner(color: Theme.text2, size: 10) }
                    Button("Test") {
                        testing = true
                        testMessage = nil
                        Task {
                            testMessage = await store.testAdvisor()
                            testing = false
                        }
                    }
                    .buttonStyle(GhostButtonStyle(compact: true))
                    .disabled(!isLocal && status?.keyPresent != true)
                }
            }

            Text("Only the finding and the results of read-only checks (registry metadata, hashes, signatures) are sent to the model. It cannot change anything: fixes come from Safeguard's fixed list, and each one waits for your approval.")
                .font(.ui(12)).foregroundStyle(Theme.text3)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 12).padding(.top, 2)
        }
        .task {
            await store.refreshAdvisor()
            sync()
            if let saved = UserDefaults.standard.object(forKey: "advisorAutoDigest") as? Bool,
               saved != (status?.autoDigest ?? false) {
                await store.saveAdvisor(["auto_digest": saved], silent: true)
            }
            if status?.enabled == true, status?.keyPresent == true || isLocal {
                await store.loadModels()
            }
        }
        .onChange(of: status?.provider) { _, _ in
            sync(force: true)
            Task { await store.loadModels(force: true) }
        }
    }

    private func sync(force: Bool = false) {
        guard force || !loaded else { return }
        baseURL = status?.baseUrl ?? ""
        loaded = true
        if UserDefaults.standard.object(forKey: "advisorAutoDigest") == nil {
            UserDefaults.standard.set(status?.autoDigest ?? false, forKey: "advisorAutoDigest")
        }
    }

    private func save(_ fields: [String: Any]) {
        Task { await store.saveAdvisor(fields) }
    }
}

// MARK: - Sharing pieces

struct AdvisorProposalCard: View {
    @Environment(AppStore.self) private var store
    let proposal: AdvisorProposal

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let text = proposal.explanation, !text.isEmpty {
                Text(text).font(.ui(13.5)).foregroundStyle(Theme.text)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 620, alignment: .leading)
            }
            if let steps = proposal.steps, !steps.isEmpty {
                VStack(alignment: .leading, spacing: 7) {
                    Text("What the agent checked").font(.ui(11.5, 500)).foregroundStyle(Theme.text3)
                    ForEach(steps) { step in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: step.ok == false ? "xmark.circle" : "checkmark.circle")
                                .font(.system(size: 11))
                                .foregroundStyle(step.ok == false ? Theme.amber : Theme.green)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(step.title).font(.ui(12.5, 500)).foregroundStyle(Theme.text)
                                if let detail = step.detail, !detail.isEmpty {
                                    Text(detail).font(.ui(12)).foregroundStyle(Theme.text2)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: Theme.corner(11), style: .continuous)
                    .fill(Theme.inset))
            }
            if let rejection = proposal.rejected {
                Text(rejection).font(.ui(12.5)).foregroundStyle(Theme.amber)
            }
            if let action = proposal.actionId {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 8) {
                        Text(proposal.title ?? action).font(.ui(14, 600)).foregroundStyle(Theme.text)
                        if let risk = proposal.risk { Pill(risk.capitalized) }
                        if proposal.needsAdmin == true { Pill("Asks for admin") }
                        Spacer()
                    }
                    if let why = proposal.why, !why.isEmpty {
                        Text(why).font(.ui(12.5)).foregroundStyle(Theme.text2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let command = proposal.command, !command.isEmpty {
                        Text(command).font(.mono(11))
                            .foregroundStyle(Theme.text2)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                            .background(RoundedRectangle(cornerRadius: Theme.corner(10), style: .continuous)
                                .fill(Theme.well))
                    }
                    HStack(spacing: 8) {
                        Button("Fix it") {
                            Task { await store.applyProposal(proposal) }
                        }
                        .buttonStyle(CoralButtonStyle(compact: true))
                        .disabled(store.fixing)
                        Button("Not now") { store.dismissProposal() }
                            .buttonStyle(GhostButtonStyle(compact: true))
                        if store.fixing { Spinner(color: Theme.text2, size: 10) }
                        Spacer()
                    }
                }
                .padding(14)
                .background(RoundedRectangle(cornerRadius: Theme.corner(12), style: .continuous)
                    .fill(Theme.inset))
            } else if proposal.rejected == nil {
                Text("No automatic fix for this one. The advice above is the safe route.")
                    .font(.ui(12.5)).foregroundStyle(Theme.text2)
            }
        }
    }
}

struct AdvisorFollowupSection: View {
    @Environment(AppStore.self) private var store
    let alert: ThreatAlert?
    let check: PostureCheck?

    @State private var question = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(store.followups) { exchange in
                VStack(alignment: .leading, spacing: 4) {
                    Text(exchange.question).font(.ui(12.5, 600)).foregroundStyle(Theme.text)
                    Text(exchange.answer).font(.ui(12.5)).foregroundStyle(Theme.text2)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .insetRow(padding: EdgeInsets(top: 10, leading: 14, bottom: 10, trailing: 14))
            }
            HStack(spacing: 8) {
                TextField("", text: $question, prompt: Text("Ask a follow-up")
                    .foregroundStyle(Theme.text3))
                    .advisorField()
                    .frame(maxWidth: .infinity)
                    .onSubmit(send)
                Button("Ask") { send() }
                    .buttonStyle(GhostButtonStyle(compact: true))
                    .disabled(store.followupBusy || question.trimmingCharacters(in: .whitespaces).isEmpty)
                if store.followupBusy { Spinner(color: Theme.text2, size: 9) }
            }
        }
    }

    private func send() {
        let text = question
        question = ""
        Task { await store.askFollowup(text, alert: alert, check: check) }
    }
}

// MARK: - Finding panel

struct AdvisorPanel: View {
    @Environment(AppStore.self) private var store
    let alert: ThreatAlert

    private var proposal: AdvisorProposal? {
        store.advisorAlertID == alert.id ? store.advisorProposal : nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "sparkles").font(.system(size: 13)).foregroundStyle(Theme.text2)
                Text("Advisor").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                Spacer()
                if store.advisorBusy { Spinner(color: Theme.text2, size: 9) }
            }

            if store.advisorBusy {
                Text("Investigating…").font(.ui(13)).foregroundStyle(Theme.text2)
                    .insetRow()
            } else if let fix = store.lastFix, fix.ok, let record = fix.record,
                      store.lastFixAlertID == alert.id {
                fixedCard(fix, record)
            } else if let proposal {
                AdvisorProposalCard(proposal: proposal)
                AdvisorFollowupSection(alert: alert, check: nil)
            } else {
                HStack(spacing: 10) {
                    Button("Ask Safeguard") {
                        Task { await store.askAdvisor(alert) }
                    }
                    .buttonStyle(LightButtonStyle(compact: true))
                    Text("Runs read-only checks on this Mac, then proposes a fix.")
                        .font(.ui(12)).foregroundStyle(Theme.text3)
                }
                .insetRow()
            }
        }
    }

    @ViewBuilder
    private func fixedCard(_ outcome: FixOutcome, _ record: FixRecord) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.green)
            VStack(alignment: .leading, spacing: 2) {
                Text(outcome.message ?? "Fixed").font(.ui(13, 500)).foregroundStyle(Theme.text)
                Text(record.title).font(.ui(12)).foregroundStyle(Theme.text3)
            }
            Spacer()
            Button("Undo") { Task { await store.undoFix(record.id) } }
                .buttonStyle(TextLinkStyle(color: Theme.text2))
        }
        .insetRow()
    }
}

// MARK: - Browser request panel

struct AdvisorRequestPanel: View {
    @Environment(AppStore.self) private var store
    let request: BrowserRequest

    private var proposal: AdvisorProposal? {
        store.advisorRequestKey == request.id ? store.advisorProposal : nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "sparkles").font(.system(size: 13)).foregroundStyle(Theme.text2)
                Text("Advisor").font(.ui(12.5, 500)).foregroundStyle(Theme.text3)
                Spacer()
                if store.advisorBusy { Spinner(color: Theme.text2, size: 9) }
            }
            if store.advisorBusy {
                Text("Checking DNS, certificate, history and rules…")
                    .font(.ui(13)).foregroundStyle(Theme.text2)
            } else if let fix = store.lastFix, fix.ok, let record = fix.record,
                      store.lastFixAlertID == request.id {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.green)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(fix.message ?? "Done").font(.ui(13, 500)).foregroundStyle(Theme.text)
                        Text(record.title).font(.ui(12)).foregroundStyle(Theme.text3)
                    }
                    Spacer()
                    Button("Undo") { Task { await store.undoFix(record.id) } }
                        .buttonStyle(TextLinkStyle(color: Theme.text2))
                }
            } else if let proposal {
                AdvisorProposalCard(proposal: proposal)
            } else {
                HStack(spacing: 10) {
                    Button("Verify this request") { Task { await store.askRequest(request) } }
                        .buttonStyle(LightButtonStyle(compact: true))
                    Text("Checks DNS, TLS, local history and browser rules, then offers block or warn.")
                        .font(.ui(12)).foregroundStyle(Theme.text3)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

// MARK: - Protection check panel

struct AdvisorCheckPanel: View {
    @Environment(AppStore.self) private var store
    let check: PostureCheck

    private var proposal: AdvisorProposal? {
        store.advisorCheckKey == check.key ? store.advisorProposal : nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if store.advisorBusy {
                HStack(spacing: 8) {
                    Spinner(color: Theme.text2, size: 9)
                    Text("Investigating…").font(.ui(13)).foregroundStyle(Theme.text2)
                }
            } else if let fix = store.lastFix, fix.ok, let record = fix.record,
                      store.lastFixAlertID == check.key {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.green)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(fix.message ?? "Fixed").font(.ui(13, 500)).foregroundStyle(Theme.text)
                        Text(record.title).font(.ui(12)).foregroundStyle(Theme.text3)
                    }
                    Spacer()
                    Button("Undo") { Task { await store.undoFix(record.id) } }
                        .buttonStyle(TextLinkStyle(color: Theme.text2))
                }
            } else if let proposal {
                AdvisorProposalCard(proposal: proposal)
                AdvisorFollowupSection(alert: nil, check: check)
            } else {
                HStack(spacing: 10) {
                    Button("Ask Safeguard") {
                        Task { await store.askCheck(check) }
                    }
                    .buttonStyle(LightButtonStyle(compact: true))
                    Text("Runs read-only checks on this Mac, then proposes a fix.")
                        .font(.ui(12)).foregroundStyle(Theme.text3)
                }
            }
        }
    }
}

struct AdvisorCheckSheet: View {
    @Environment(\.dismiss) private var dismiss
    let check: PostureCheck

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(check.name).font(.display(22)).foregroundStyle(Theme.text)
                    Text(check.detail).font(.mono(11)).foregroundStyle(Theme.text3).lineLimit(2)
                }
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(GhostButtonStyle(compact: true))
            }
            ScrollView {
                AdvisorCheckPanel(check: check)
            }
            .scrollIndicators(.never)
        }
        .padding(24)
        .frame(width: 660, height: 560)
        .background(Color(nsColor: Theme.windowBackground))
    }
}

// MARK: - Whole-scan digest

struct AdvisorDigestSheet: View {
    @Environment(AppStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Brief me").font(.display(26)).foregroundStyle(Theme.text)
                    Text("A calm summary of the latest scan. Nothing is changed.")
                        .font(.ui(12.5)).foregroundStyle(Theme.text3)
                }
                Spacer()
                if store.digestBusy { Spinner(color: Theme.text2, size: 10) }
                Button("Refresh") { Task { await store.askDigest() } }
                    .buttonStyle(GhostButtonStyle(compact: true))
                    .disabled(store.digestBusy)
                Button("Done") { dismiss() }.buttonStyle(LightButtonStyle(compact: true))
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let digest = store.advisorDigest {
                        if let message = digest.error {
                            Text(message).font(.ui(13)).foregroundStyle(Theme.amber)
                        }
                        if let summary = digest.summary, !summary.isEmpty {
                            Text(summary).font(.ui(14.5)).foregroundStyle(Theme.text)
                                .lineSpacing(3)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        ForEach(Array((digest.priorities ?? []).enumerated()), id: \.offset) { i, point in
                            VStack(alignment: .leading, spacing: 5) {
                                Text("\(i + 1). \(point.finding)")
                                    .font(.ui(13.5, 600)).foregroundStyle(Theme.text)
                                if !point.why.isEmpty {
                                    Text(point.why).font(.ui(12.5)).foregroundStyle(Theme.text2)
                                }
                                if !point.next.isEmpty {
                                    Text(point.next).font(.ui(12.5)).foregroundStyle(Theme.accentText)
                                }
                            }
                            .padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(RoundedRectangle(cornerRadius: Theme.corner(12), style: .continuous)
                                .fill(Theme.inset))
                        }
                        if let model = digest.model {
                            Text("Written by \(model). \(digest.generatedAt ?? "")")
                                .font(.ui(11)).foregroundStyle(Theme.dim)
                        }
                    } else if !store.digestBusy {
                        Text("Press Refresh to ask for a briefing.").font(.ui(13)).foregroundStyle(Theme.text2)
                    }
                }
            }
            .scrollIndicators(.never)
        }
        .padding(24)
        .frame(width: 680, height: 560)
        .background(Color(nsColor: Theme.windowBackground))
        .task { if store.advisorDigest == nil { await store.askDigest() } }
    }
}
