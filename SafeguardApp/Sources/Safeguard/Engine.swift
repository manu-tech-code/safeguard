import Foundation

struct EngineFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

private struct ErrorPayload: Decodable { let error: String }
struct Empty: Decodable {}

/// Runs the bundled safeguard.py detection engine and decodes its JSON answers.
enum Engine {
    static let python = "/usr/bin/python3"

    static var scriptPath: String? {
        if let p = ProcessInfo.processInfo.environment["SAFEGUARD_ENGINE"] { return p }
        return Bundle.main.path(forResource: "safeguard", ofType: "py")
    }

    static func call<T: Decodable>(_ type: T.Type, _ args: [String],
                                   environment: [String: String] = [:]) async throws -> T {
        guard let script = scriptPath else {
            throw EngineFailure(message: "The detection engine (safeguard.py) is missing from the app bundle.")
        }
        let data: Data = try await Task.detached(priority: .userInitiated) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: python)
            p.arguments = ["-I", script, "api"] + args
            let out = Pipe()
            var env = ProcessInfo.processInfo.environment
            for (key, value) in environment { env[key] = value }
            p.environment = env
            p.standardOutput = out
            p.standardError = FileHandle.nullDevice
            p.standardInput = FileHandle.nullDevice
            try p.run()
            let d = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return d
        }.value

        let dec = JSONDecoder()
        dec.keyDecodingStrategy = .convertFromSnakeCase
        if let e = try? dec.decode(ErrorPayload.self, from: data) {
            throw EngineFailure(message: "Engine error: \(e.error)")
        }
        do {
            return try dec.decode(T.self, from: data)
        } catch {
            throw EngineFailure(message: data.isEmpty
                ? "The engine produced no output. Is Python 3 available at /usr/bin/python3?"
                : "Couldn't read the engine's answer: \(error.localizedDescription)")
        }
    }

    static func run(_ args: [String]) async throws {
        _ = try await call(Empty.self, args)
    }
}
