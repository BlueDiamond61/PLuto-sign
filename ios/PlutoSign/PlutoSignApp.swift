import SwiftUI
import UniformTypeIdentifiers
import ZIPFoundation
import Security

struct IPARecord: Identifiable, Codable {
    var id = UUID()
    var name: String
    var path: String
    var app: String
    var bundle: String
    var version: String
    var build: String
    var size: Int64
    var url: URL { URL(fileURLWithPath: path) }
}
struct AssetRecord: Identifiable, Codable {
    var id = UUID()
    var name: String
    var kind: String
    var path: String
    var detail: String? = nil
}
struct ImportedFileRecord: Identifiable, Codable {
    var id = UUID()
    var name: String
    var path: String
    var fileType: String
    var size: Int64
    var url: URL { URL(fileURLWithPath: path) }
}
struct ArchiveRecord: Identifiable, Hashable {
    var id: String { path }
    var name: String
    var path: String
    var folder: Bool
    var size: Int64
}
struct BundleRecord: Identifiable {
    var id: String { path }
    var path: String
    var kind: String
    var bundleID: String
    var version: String
    var build: String
}
enum PlutoError: LocalizedError {
    case archive, info, plist, missing, unsafe, large, invalidFile, keychain(OSStatus)
    var errorDescription: String? {
        switch self {
        case .archive: return "This IPA is not a readable ZIP archive."
        case .info: return "The main app Info.plist was not found."
        case .plist: return "The property list is invalid."
        case .missing: return "The archive item could not be found."
        case .unsafe: return "An unsafe archive path was blocked."
        case .large: return "This file is too large for the built-in preview."
        case .invalidFile: return "The selected file is not a supported signing asset."
        case .keychain(let status): return "Keychain error: \(status). Check the P12 password and try again."
        }
    }
}
enum PlutoStorage {
    static let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("PlutoSign")
    static let ipas = root.appendingPathComponent("IPAs")
    static let profiles = root.appendingPathComponent("Profiles")
    static let documents = root.appendingPathComponent("Documents")
    static let exports = root.appendingPathComponent("Exports")
    static let library = root.appendingPathComponent("library.json")
    static func prepare() throws {
        for url in [root, ipas, profiles, documents, exports] {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        }
    }
    static func unique(_ name: String, in folder: URL) -> URL {
        let input = URL(fileURLWithPath: name)
        let stem = input.deletingPathExtension().lastPathComponent
        let ext = input.pathExtension
        var result = folder.appendingPathComponent(name)
        var index = 2
        while FileManager.default.fileExists(atPath: result.path) {
            result = folder.appendingPathComponent(ext.isEmpty ? "\(stem)-\(index)" : "\(stem)-\(index).\(ext)")
            index += 1
        }
        return result
    }
}
enum PlutoKeychain {
    static func validateP12(_ data: Data, password: String) throws {
        var result: CFArray?
        let status = SecPKCS12Import(data as CFData, [kSecImportExportPassphrase as String: password] as CFDictionary, &result)
        guard status == errSecSuccess else { throw PlutoError.keychain(status) }
        guard let rows = result as? [[String: Any]], rows.contains(where: { $0[kSecImportItemIdentity as String] != nil }) else {
            throw PlutoError.keychain(errSecDecode)
        }
    }
    static func save(_ data: Data, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.plutosign.signing-assets",
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw PlutoError.keychain(status) }
    }
    static func remove(_ account: String) -> Bool {
        let status = SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.plutosign.signing-assets",
            kSecAttrAccount as String: account
        ] as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    static func contains(_ account: String) -> Bool {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.plutosign.signing-assets",
            kSecAttrAccount as String: account,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as CFDictionary, &result)
        return status == errSecSuccess
    }
}
enum IPAService {
    static func safe(_ raw: String) -> String? {
        var value = raw.replacingOccurrences(of: "\\", with: "/")
        while value.hasSuffix("/") { value.removeLast() }
        guard !value.isEmpty, !value.hasPrefix("/"), !value.contains("\0") else { return nil }

        // Reject traversal, empty path segments and drive-style paths before
        // passing archive names to FileManager or ZIPFoundation.
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              !parts[0].contains(":") else { return nil }
        return parts.joined(separator: "/")
    }

    static func read(_ ipa: URL, _ path: String, max: Int = 2_000_000) throws -> Data {
        guard let safePath = safe(path) else { throw PlutoError.unsafe }
        guard max >= 0,
              let archive = Archive(url: ipa, accessMode: .read),
              let entry = archive[safePath] else { throw PlutoError.missing }
        guard entry.type == .file else { throw PlutoError.plist }
        guard entry.uncompressedSize <= UInt64(max) else { throw PlutoError.large }

        var data = Data()
        data.reserveCapacity(Int(entry.uncompressedSize))
        _ = try archive.extract(entry) { chunk in
            guard chunk.count <= max - data.count else { throw PlutoError.large }
            data.append(chunk)
        }
        return data
    }
    static func metadata(_ ipa: URL) throws -> (String, String, String, String) {
        guard let archive = Archive(url: ipa, accessMode: .read) else { throw PlutoError.archive }
        let paths = archive.map(\.path).filter {
            let lower = $0.lowercased()
            return lower.hasPrefix("payload/") && lower.hasSuffix(".app/info.plist")
        }
            .sorted { $0.split(separator: "/").count < $1.split(separator: "/").count }
        guard let path = paths.first else { throw PlutoError.info }
        guard let info = try PropertyListSerialization.propertyList(from: read(ipa, path, max: 4_000_000), options: [], format: nil) as? [String: Any] else { throw PlutoError.plist }
        return (
            info["CFBundleDisplayName"] as? String ?? info["CFBundleName"] as? String ?? ipa.deletingPathExtension().lastPathComponent,
            info["CFBundleIdentifier"] as? String ?? "Unknown",
            info["CFBundleShortVersionString"] as? String ?? "Unknown",
            info["CFBundleVersion"] as? String ?? "Unknown"
        )
    }
    static func list(_ ipa: URL, folder: String) throws -> [ArchiveRecord] {
        guard let archive = Archive(url: ipa, accessMode: .read) else { throw PlutoError.archive }
        let safeFolder: String
        if folder.isEmpty { safeFolder = "" }
        else {
            guard let normalized = safe(folder) else { throw PlutoError.unsafe }
            safeFolder = normalized
        }
        let prefix = safeFolder.isEmpty ? "" : safeFolder + "/"
        var result: [String: ArchiveRecord] = [:]
        for entry in archive {
            guard let path = safe(entry.path) else { continue }
            let relative: String
            if prefix.isEmpty { relative = path }
            else { guard path.hasPrefix(prefix) else { continue }; relative = String(path.dropFirst(prefix.count)) }
            guard !relative.isEmpty, let first = relative.split(separator: "/").first else { continue }
            let name = String(first)
            let child = prefix + name
            if relative.split(separator: "/").count > 1 {
                result[child] = ArchiveRecord(name: name, path: child, folder: true, size: 0)
            } else {
                let isFolder = entry.type == .directory
                result[child] = ArchiveRecord(name: name, path: child, folder: isFolder, size: isFolder ? 0 : Int64(clamping: entry.uncompressedSize))
            }
        }
        return result.values.sorted {
            if $0.folder != $1.folder { return $0.folder }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }
    static func search(_ ipa: URL, query: String, contents: Bool) throws -> [ArchiveRecord] {
        guard let archive = Archive(url: ipa, accessMode: .read) else { throw PlutoError.archive }
        let term = query.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !term.isEmpty else { return [] }
        let readable: Set<String> = ["plist", "xml", "json", "txt", "strings", "csv", "md", "html"]
        var found: [ArchiveRecord] = []
        for entry in archive where entry.type == .file {
            guard let path = safe(entry.path) else { continue }
            var match = path.lowercased().contains(term)
            let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
            if !match && contents && readable.contains(ext) && entry.uncompressedSize < 500_000 {
                let data = try read(ipa, path, max: 500_000)
                match = String(data: data, encoding: .utf8)?.localizedCaseInsensitiveContains(term) ?? false
            }
            if match { found.append(ArchiveRecord(name: URL(fileURLWithPath: path).lastPathComponent, path: path, folder: false, size: Int64(clamping: entry.uncompressedSize))) }
        }
        return found.sorted { $0.path.localizedCaseInsensitiveCompare($1.path) == .orderedAscending }
    }
    static func versions(_ ipa: URL) throws -> [BundleRecord] {
        guard let archive = Archive(url: ipa, accessMode: .read) else { throw PlutoError.archive }
        let paths = archive.map(\.path).filter {
            let lower = $0.lowercased()
            return lower.hasSuffix(".app/info.plist") || lower.hasSuffix(".appex/info.plist") || lower.hasSuffix(".framework/info.plist")
        }
        return try paths.map { path in
            guard let info = try PropertyListSerialization.propertyList(from: read(ipa, path, max: 4_000_000), options: [], format: nil) as? [String: Any] else { throw PlutoError.plist }
            let lower = path.lowercased()
            return BundleRecord(path: path,
                                kind: lower.contains(".appex/") ? "Extension" : (lower.contains(".framework/") ? "Framework" : "App"),
                                bundleID: info["CFBundleIdentifier"] as? String ?? "Unknown",
                                version: info["CFBundleShortVersionString"] as? String ?? "—",
                                build: info["CFBundleVersion"] as? String ?? "—")
        }
    }
    static func synchronize(_ ipa: URL, version: String, build: String) throws -> URL {
        let versionPattern = #"^[0-9]+(\.[0-9]+){0,3}$"#
        let buildPattern = #"^[A-Za-z0-9._-]{1,64}$"#
        guard version.range(of: versionPattern, options: .regularExpression) != nil,
              build.range(of: buildPattern, options: .regularExpression) != nil,
              let input = Archive(url: ipa, accessMode: .read) else { throw PlutoError.info }

        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let tree = temp.appendingPathComponent("PayloadTree", isDirectory: true)
        try FileManager.default.createDirectory(at: tree, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }

        var expandedBytes: UInt64 = 0
        var entryCount = 0
        for entry in input {
            guard let path = safe(entry.path) else { throw PlutoError.unsafe }
            guard entry.type != .symlink else { throw PlutoError.unsafe }
            entryCount += 1
            guard entryCount <= 50_000 else { throw PlutoError.large }
            let (nextTotal, overflow) = expandedBytes.addingReportingOverflow(entry.uncompressedSize)
            guard !overflow, nextTotal <= 4_000_000_000 else { throw PlutoError.large }
            expandedBytes = nextTotal

            let dest = tree.appendingPathComponent(path)
            if entry.type == .directory {
                try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true)
            } else {
                try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
                _ = try input.extract(entry, to: dest)
            }
        }
        var changed = 0
        let walker = FileManager.default.enumerator(at: tree, includingPropertiesForKeys: [.isRegularFileKey])
        while let file = walker?.nextObject() as? URL {
            guard file.lastPathComponent.lowercased() == "info.plist" else { continue }
            let relative = String(file.path.dropFirst(tree.path.count + 1)).lowercased()
            guard relative.contains(".app/") || relative.contains(".appex/") else { continue }
            guard var dict = try PropertyListSerialization.propertyList(from: Data(contentsOf: file), options: [], format: nil) as? [String: Any] else { continue }
            dict["CFBundleShortVersionString"] = version
            dict["CFBundleVersion"] = build
            let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
            try data.write(to: file, options: .atomic)
            changed += 1
        }
        guard changed > 0 else { throw PlutoError.info }
        let outputName = "\(ipa.deletingPathExtension().lastPathComponent)-VersionSync-\(version).ipa"
        let temporaryArchive = temp.appendingPathComponent("Synchronized.ipa")
        guard let output = Archive(url: temporaryArchive, accessMode: .create) else { throw PlutoError.archive }
        let files = FileManager.default.enumerator(at: tree, includingPropertiesForKeys: [.isRegularFileKey])
        while let file = files?.nextObject() as? URL {
            if (try? file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                try output.addEntry(with: String(file.path.dropFirst(tree.path.count + 1)), fileURL: file, compressionMethod: .deflate)
            }
        }
        let verifiedMetadata = try metadata(temporaryArchive)
        guard verifiedMetadata.2 == version, verifiedMetadata.3 == build else {
            throw PlutoError.plist
        }
        let outputURL = PlutoStorage.unique(outputName, in: PlutoStorage.exports)
        try FileManager.default.moveItem(at: temporaryArchive, to: outputURL)
        return outputURL
    }
}
@MainActor final class PlutoStore: ObservableObject {
    @Published var ipas: [IPARecord] = []
    @Published var assets: [AssetRecord] = []
    @Published var documents: [ImportedFileRecord] = []
    @Published var activity: [String] = []
    @Published var error: String?

    private struct Library: Codable {
        var ipas: [IPARecord] = []
        var assets: [AssetRecord] = []
        var documents: [ImportedFileRecord] = []
        var activity: [String] = []
        enum CodingKeys: String, CodingKey { case ipas, assets, documents, activity }
        init(ipas: [IPARecord] = [], assets: [AssetRecord] = [], documents: [ImportedFileRecord] = [], activity: [String] = []) {
            self.ipas = ipas
            self.assets = assets
            self.documents = documents
            self.activity = activity
        }
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            ipas = try c.decodeIfPresent([IPARecord].self, forKey: .ipas) ?? []
            assets = try c.decodeIfPresent([AssetRecord].self, forKey: .assets) ?? []
            documents = try c.decodeIfPresent([ImportedFileRecord].self, forKey: .documents) ?? []
            activity = try c.decodeIfPresent([String].self, forKey: .activity) ?? []
        }
    }

    init() {
        do {
            try PlutoStorage.prepare()
            reload()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func reload() {
        guard FileManager.default.fileExists(atPath: PlutoStorage.library.path) else { return }
        do {
            let data = try Data(contentsOf: PlutoStorage.library)
            let lib = try JSONDecoder().decode(Library.self, from: data)
            ipas = lib.ipas.filter { FileManager.default.fileExists(atPath: $0.path) }
            assets = lib.assets.filter {
                if $0.path.hasPrefix("keychain:") {
                    return PlutoKeychain.contains(String($0.path.dropFirst(9)))
                }
                return FileManager.default.fileExists(atPath: $0.path)
            }
            documents = lib.documents.filter { FileManager.default.fileExists(atPath: $0.path) }
            activity = Array(lib.activity.prefix(12))

            if ipas.count != lib.ipas.count || assets.count != lib.assets.count ||
                documents.count != lib.documents.count || activity.count != lib.activity.count {
                save()
            }
        } catch {
            self.error = "Your saved library could not be read. The original library file was left untouched. \(error.localizedDescription)"
        }
    }

    private func save() {
        do {
            let lib = Library(ipas: ipas, assets: assets, documents: documents, activity: activity)
            try JSONEncoder().encode(lib).write(to: PlutoStorage.library, options: .atomic)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func log(_ value: String) {
        activity.insert(value, at: 0)
        activity = Array(activity.prefix(12))
        save()
    }

    func addSynchronizedIPA(_ ipa: IPARecord) {
        ipas.removeAll { $0.id == ipa.id || $0.path == ipa.path }
        ipas.insert(ipa, at: 0)
        activity.insert("Saved version-synchronized IPA: \(ipa.version) (build \(ipa.build))", at: 0)
        activity = Array(activity.prefix(12))
        save()
    }

    func importIPAs(_ urls: [URL]) {
        for url in urls {
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            var destination: URL?
            do {
                let dest = PlutoStorage.unique(url.lastPathComponent, in: PlutoStorage.ipas)
                destination = dest
                try FileManager.default.copyItem(at: url, to: dest)
                let info = try IPAService.metadata(dest)
                let size = (try? FileManager.default.attributesOfItem(atPath: dest.path)[.size] as? NSNumber)?.int64Value ?? 0
                ipas.insert(IPARecord(name: dest.lastPathComponent, path: dest.path, app: info.0, bundle: info.1,
                                      version: info.2, build: info.3, size: size), at: 0)
                log("Imported IPA: \(info.0)")
            } catch {
                if let destination { try? FileManager.default.removeItem(at: destination) }
                self.error = "Could not import \(url.lastPathComponent): \(error.localizedDescription)"
            }
        }
        save()
    }

    func importProfile(_ url: URL) {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        do {
            guard url.pathExtension.lowercased() == "mobileprovision" else { throw PlutoError.invalidFile }
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let fileSize = (attributes[.size] as? NSNumber)?.int64Value ?? 0
            guard fileSize > 0 else { throw PlutoError.invalidFile }
            guard fileSize <= 10 * 1_024 * 1_024 else { throw PlutoError.large }
            let dest = PlutoStorage.unique(url.lastPathComponent, in: PlutoStorage.profiles)
            try FileManager.default.copyItem(at: url, to: dest)
            let detail = "Stored locally • Profile expiry, App ID, entitlements and certificate compatibility must be validated by the authorized macOS signing workflow."
            assets.insert(AssetRecord(name: dest.lastPathComponent, kind: "Provisioning Profile", path: dest.path, detail: detail), at: 0)
            log("Imported provisioning profile")
        } catch {
            self.error = error.localizedDescription
        }
    }

    func importFiles(_ urls: [URL]) {
        for url in urls {
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            let ext = url.pathExtension.lowercased()
            if ext == "ipa" {
                importIPAs([url])
                continue
            }
            if ext == "mobileprovision" {
                importProfile(url)
                continue
            }
            do {
                let dest = PlutoStorage.unique(url.lastPathComponent, in: PlutoStorage.documents)
                try FileManager.default.copyItem(at: url, to: dest)
                let attributes = try FileManager.default.attributesOfItem(atPath: dest.path)
                let size = (attributes[.size] as? NSNumber)?.int64Value ?? 0
                documents.insert(ImportedFileRecord(name: dest.lastPathComponent, path: dest.path,
                                                     fileType: ext.isEmpty ? "FILE" : ext.uppercased(), size: size), at: 0)
                log("Imported file: \(dest.lastPathComponent)")
            } catch {
                self.error = error.localizedDescription
            }
        }
        save()
    }

    func importP12(_ data: Data, name: String, password: String) throws {
        let ext = URL(fileURLWithPath: name).pathExtension.lowercased()
        guard ["p12", "pfx"].contains(ext), !data.isEmpty else { throw PlutoError.invalidFile }
        guard data.count <= 20 * 1_024 * 1_024 else { throw PlutoError.large }
        try PlutoKeychain.validateP12(data, password: password)
        let account = UUID().uuidString
        try PlutoKeychain.save(data, account: account)
        assets.insert(AssetRecord(name: name, kind: "P12 / PFX", path: "keychain:" + account,
                                  detail: "Password checked • Identity found • Protected in Keychain"), at: 0)
        log("Stored certificate identity in Keychain")
    }

    func remove(_ asset: AssetRecord) {
        do {
            if asset.path.hasPrefix("keychain:") {
                let account = String(asset.path.dropFirst(9))
                guard PlutoKeychain.remove(account) else {
                    self.error = "Keychain could not remove this signing identity. Try again."
                    return
                }
            } else {
                try FileManager.default.removeItem(atPath: asset.path)
            }
            assets.removeAll { $0.id == asset.id }
            log("Removed \(asset.name)")
        } catch {
            self.error = "Could not remove \(asset.name): \(error.localizedDescription)"
        }
    }

    func remove(_ ipa: IPARecord) {
        do {
            try FileManager.default.removeItem(at: ipa.url)
            ipas.removeAll { $0.id == ipa.id }
            log("Removed \(ipa.name)")
        } catch {
            self.error = "Could not remove \(ipa.name): \(error.localizedDescription)"
        }
    }

    func removeDocument(_ file: ImportedFileRecord) {
        do {
            try FileManager.default.removeItem(at: file.url)
            documents.removeAll { $0.id == file.id }
            log("Removed file \(file.name)")
        } catch {
            self.error = "Could not remove \(file.name): \(error.localizedDescription)"
        }
    }

    func signingReadiness(_ ipa: IPARecord, certificate: AssetRecord?, profile: AssetRecord?) -> String {
        guard let certificate, certificate.kind == "P12 / PFX",
              certificate.path.hasPrefix("keychain:"),
              PlutoKeychain.contains(String(certificate.path.dropFirst(9))) else {
            return "Select an available P12/PFX identity stored in Keychain."
        }
        guard let profile, profile.kind == "Provisioning Profile",
              FileManager.default.fileExists(atPath: profile.path) else {
            return "Select an imported provisioning profile."
        }
        let ipaExists = FileManager.default.fileExists(atPath: ipa.path)
        guard ipaExists else { return "The selected IPA file is missing. Re-import it from Files." }
        return "Required inputs are selected: IPA, P12/PFX identity and provisioning profile. This is an import check only—not proof that the certificate and profile match. The authorized macOS signing workflow must validate profile expiry, bundle ID, entitlements, device/distribution type, certificate pairing and the final signature."
    }

    func signingRequest(_ ipa: IPARecord, _ cert: AssetRecord?, _ profile: AssetRecord?) throws -> URL {
        guard FileManager.default.fileExists(atPath: ipa.path),
              let cert, cert.kind == "P12 / PFX", cert.path.hasPrefix("keychain:"),
              PlutoKeychain.contains(String(cert.path.dropFirst(9))),
              let profile, profile.kind == "Provisioning Profile",
              FileManager.default.fileExists(atPath: profile.path) else {
            throw PlutoError.missing
        }

        let formatter = ISO8601DateFormatter()
        let request: [String: Any] = [
            "schema_version": 1,
            "created_at": formatter.string(from: Date()),
            "ipa": [
                "filename": ipa.name,
                "bundle_id": ipa.bundle,
                "version": ipa.version,
                "build": ipa.build
            ],
            "certificate": ["filename": cert.name, "stored_in_keychain": true],
            "provisioning_profile": ["filename": profile.name],
            "status": "Handoff request only. No certificate bytes, password, private key, or signed IPA are included."
        ]
        let json = try JSONSerialization.data(withJSONObject: request, options: [.prettyPrinted, .sortedKeys])
        let url = PlutoStorage.unique("SigningRequest-\(UUID().uuidString.prefix(8)).json", in: PlutoStorage.exports)
        try json.write(to: url, options: .atomic)
        return url
    }
}
@main struct PlutoSignApp: App {
    @StateObject private var store = PlutoStore()
    var body: some Scene { WindowGroup { PlutoTabs().environmentObject(store).preferredColorScheme(.dark) } }
}
enum Style {
    static let bg = Color(red: 0.035, green: 0.025, blue: 0.065)
    static let card = Color(red: 0.09, green: 0.065, blue: 0.14)
    static let violet = Color(red: 0.63, green: 0.40, blue: 1)
    static let pink = Color(red: 0.82, green: 0.49, blue: 0.96)
    static let muted = Color(red: 0.68, green: 0.64, blue: 0.77)
}
struct Panel<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(16)
            .background(
                LinearGradient(colors: [Style.card, Color(red: 0.065, green: 0.045, blue: 0.11)],
                               startPoint: .topLeading, endPoint: .bottomTrailing),
                in: RoundedRectangle(cornerRadius: 21, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 21, style: .continuous)
                    .stroke(.white.opacity(0.075), lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.16), radius: 15, x: 0, y: 8)
    }
}
struct MainButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 15)
            .padding(.vertical, 14)
            .background(
                LinearGradient(colors: [Style.violet, Style.pink],
                               startPoint: .leading, endPoint: .trailing),
                in: RoundedRectangle(cornerRadius: 15, style: .continuous)
            )
            .shadow(color: Style.violet.opacity(configuration.isPressed ? 0.08 : 0.24),
                    radius: 12, x: 0, y: 5)
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
    }
}
struct PlutoTabs: View {
    @EnvironmentObject var store: PlutoStore
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            Dashboard(selectedTab: $selectedTab)
                .tabItem { Label("Home", systemImage: "square.grid.2x2.fill") }
                .tag(0)

            Library()
                .tabItem { Label("View IPAs", systemImage: "shippingbox.fill") }
                .tag(1)

            ImportedFiles()
                .tabItem { Label("Files", systemImage: "folder.fill") }
                .tag(2)

            Assets()
                .tabItem { Label("Cert Import", systemImage: "key.fill") }
                .tag(3)

            SignPrep()
                .tabItem { Label("Sign IPA", systemImage: "signature") }
                .tag(4)
        }
        .tint(Style.violet)
        .toolbarBackground(Style.card, for: .tabBar)
        .toolbarBackground(.visible, for: .tabBar)
        .onAppear { store.reload() }
        .alert("Pluto Sign", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
            Button("OK") { store.error = nil }
        } message: {
            Text(store.error ?? "")
        }
    }
}

struct Dashboard: View {
    @EnvironmentObject var store: PlutoStore
    @Binding var selectedTab: Int
    @State private var importing = false
    @State private var importingFiles = false

    var body: some View {
        NavigationStack {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 19) {
                    header
                    hero
                    metrics
                    quickActions
                    profileCard
                    activityCard
                    footer
                }
                .padding(.horizontal, 18)
                .padding(.top, 18)
                .padding(.bottom, 28)
            }
            .background(Style.bg.ignoresSafeArea())
            .toolbar(.hidden, for: .navigationBar)
            .fileImporter(isPresented: $importing,
                          allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data],
                          allowsMultipleSelection: true) { result in
                switch result {
                case .success(let urls): store.importIPAs(urls)
                case .failure(let error): store.error = error.localizedDescription
                }
            }
            .fileImporter(isPresented: $importingFiles, allowedContentTypes: [.item],
                          allowsMultipleSelection: true) { result in
                switch result {
                case .success(let urls): store.importFiles(urls)
                case .failure(let error): store.error = error.localizedDescription
                }
            }
            .refreshable { store.reload() }
        }
        .tint(Style.violet)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("PLUTO SIGN")
                    .font(.system(size: 13, weight: .black, design: .rounded))
                    .tracking(2.6)
                    .foregroundStyle(Style.pink)
                Text("Workspace")
                    .font(.system(size: 27, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
            }
            Spacer()
            ZStack {
                Circle().fill(Style.violet.opacity(0.16))
                Circle().stroke(Style.violet.opacity(0.3), lineWidth: 1)
                Image(systemName: "sparkles.rectangle.stack.fill")
                    .font(.system(size: 21, weight: .semibold))
                    .foregroundStyle(Style.pink)
            }
            .frame(width: 49, height: 49)
        }
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 13) {
            HStack(spacing: 7) {
                Circle().fill(Style.pink).frame(width: 7, height: 7)
                Text("LOCAL PACKAGE WORKSPACE")
                    .font(.system(size: 10, weight: .bold, design: .rounded))
                    .tracking(1.25)
                    .foregroundStyle(.white.opacity(0.84))
            }
            Text("Everything for your\nIPA workflow.")
                .font(.system(size: 29, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
                .fixedSize(horizontal: false, vertical: true)
            Text("Import packages, explore archive contents, manage your own signing files and prepare an authorized signing request.")
                .font(.subheadline)
                .foregroundStyle(.white.opacity(0.79))
                .fixedSize(horizontal: false, vertical: true)
            Button { importing = true } label: {
                Label("Import an IPA", systemImage: "plus")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(MainButton())
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            LinearGradient(colors: [
                Color(red: 0.30, green: 0.16, blue: 0.52),
                Color(red: 0.18, green: 0.10, blue: 0.34),
                Color(red: 0.12, green: 0.08, blue: 0.22)
            ], startPoint: .topLeading, endPoint: .bottomTrailing),
            in: RoundedRectangle(cornerRadius: 25, style: .continuous)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 25, style: .continuous)
                .stroke(.white.opacity(0.12), lineWidth: 1)
        )
        .shadow(color: Style.violet.opacity(0.17), radius: 22, x: 0, y: 10)
    }

    private var metrics: some View {
        HStack(spacing: 10) {
            metricCard("IPA PACKAGES", value: store.ipas.count, icon: "shippingbox.fill")
            metricCard("FILES", value: store.documents.count, icon: "folder.fill")
            metricCard("SIGNING ASSETS", value: store.assets.count, icon: "key.fill")
        }
    }

    private var quickActions: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeading("QUICK ACCESS", subtitle: "Jump into a workspace")
            HStack(spacing: 11) {
                actionTile("View IPAs", detail: "Package library", icon: "shippingbox.fill") {
                    selectedTab = 1
                }
                actionTile("My Files", detail: "Documents & exports", icon: "folder.fill") {
                    selectedTab = 2
                }
            }
            HStack(spacing: 11) {
                actionTile("Cert Import", detail: "Your P12 & profiles", icon: "key.fill") {
                    selectedTab = 3
                }
                actionTile("Sign IPA", detail: "Prepare an authorized signing handoff", icon: "signature") {
                    selectedTab = 4
                }
            }
            Button { importingFiles = true } label: {
                Label("Import other files from Files", systemImage: "folder.badge.plus")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .tint(Style.violet)
        }
    }

    private var profileCard: some View {
        Panel {
            HStack(alignment: .top, spacing: 13) {
                ZStack {
                    RoundedRectangle(cornerRadius: 13).fill(Style.violet.opacity(0.17))
                    Image(systemName: "person.crop.square.badge.plus")
                        .font(.system(size: 20))
                        .foregroundStyle(Style.pink)
                }
                .frame(width: 43, height: 43)
                VStack(alignment: .leading, spacing: 5) {
                    Text("HOME SCREEN PROFILE")
                        .font(.caption.bold())
                        .tracking(0.8)
                        .foregroundStyle(Style.pink)
                    Text("Add the Pluto Sign homepage to your Home Screen.")
                        .font(.subheadline)
                        .foregroundStyle(.white)
                    Text("Install the removable Home Screen shortcut, or check the latest published app release.")
                        .font(.caption)
                        .foregroundStyle(Style.muted)
                    HStack(spacing: 14) {
                        Link(destination: URL(string: "https://bluediamond61.github.io/PLuto-sign/pluto-sign-home.mobileconfig")!) {
                            Label("Download profile", systemImage: "arrow.down.circle")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(Style.violet)
                        }
                        Link(destination: URL(string: "https://github.com/BlueDiamond61/PLuto-sign/releases")!) {
                            Label("Update App", systemImage: "arrow.up.circle")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(Style.violet)
                        }
                    }
                    Link(destination: URL(string: "https://bluediamond61.github.io/PLuto-sign/")!) {
                        Label("Open profile page", systemImage: "arrow.up.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(Style.violet)
                    }
                }
                Spacer(minLength: 0)
            }
        }
    }

    private var activityCard: some View {
        Panel {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("RECENT ACTIVITY")
                        .font(.caption.bold())
                        .tracking(0.8)
                        .foregroundStyle(Style.muted)
                    Spacer()
                    Text("\(store.activity.count) events")
                        .font(.caption2)
                        .foregroundStyle(Style.muted)
                }
                if store.activity.isEmpty {
                    HStack(spacing: 10) {
                        Image(systemName: "clock")
                            .foregroundStyle(Style.muted)
                        Text("Your imports and exports will appear here.")
                            .font(.subheadline)
                            .foregroundStyle(Style.muted)
                    }
                } else {
                    ForEach(Array(store.activity.prefix(5).enumerated()), id: \.offset) { _, item in
                        HStack(alignment: .top, spacing: 9) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.caption)
                                .foregroundStyle(Style.violet)
                                .padding(.top, 2)
                            Text(item)
                                .font(.subheadline)
                                .foregroundStyle(.white.opacity(0.9))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
        }
    }

    private var footer: some View {
        Text("Pluto Sign manages local packages and signing inputs. Actual app signing and device distribution require an authorized Apple workflow.")
            .font(.caption2)
            .foregroundStyle(Style.muted)
            .frame(maxWidth: .infinity, alignment: .center)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 8)
    }

    private func metricCard(_ title: String, value: Int, icon: String) -> some View {
        Panel {
            VStack(alignment: .leading, spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Style.pink)
                Text("\(value)")
                    .font(.system(size: 25, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .contentTransition(.numericText())
                Text(title)
                    .font(.system(size: 9, weight: .bold, design: .rounded))
                    .tracking(0.4)
                    .foregroundStyle(Style.muted)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func sectionHeading(_ title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.caption.bold())
                .tracking(1)
                .foregroundStyle(Style.pink)
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(Style.muted)
        }
    }

    private func actionTile(_ title: String, detail: String, icon: String,
                            action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 11) {
                Image(systemName: icon)
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(Style.pink)
                    .frame(width: 37, height: 37)
                    .background(Style.violet.opacity(0.16), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.white)
                    Text(detail)
                        .font(.caption2)
                        .foregroundStyle(Style.muted)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 96, alignment: .leading)
            .padding(13)
            .background(Style.card, in: RoundedRectangle(cornerRadius: 19, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 19, style: .continuous)
                    .stroke(.white.opacity(0.07), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}

struct Library: View {
    @EnvironmentObject var store: PlutoStore
    @State private var importing = false
    @State private var importingFiles = false
    @State private var query = ""
    var items: [IPARecord] { store.ipas.filter { query.isEmpty || "\($0.app) \($0.bundle) \($0.version) \($0.name)".localizedCaseInsensitiveContains(query) } }
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 13) {
                    Text("View IPAs").font(.system(size: 26, weight: .bold, design: .rounded))
                    Button { importing = true } label: { Label("Import IPA", systemImage: "plus").frame(maxWidth: .infinity) }.buttonStyle(MainButton())
                    Button { importingFiles = true } label: { Label("Import Files", systemImage: "folder.badge.plus").frame(maxWidth: .infinity) }.buttonStyle(.bordered).tint(Style.violet)
                    TextField("Search app, bundle ID, version…", text: $query).padding(12).background(Style.card, in: RoundedRectangle(cornerRadius: 12))
                    ForEach(items) { ipa in
                        NavigationLink(destination: IPADetail(ipa: ipa)) {
                            Panel {
                                HStack {
                                    Image(systemName: "app.dashed").font(.title2).foregroundStyle(Style.pink)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(ipa.app).font(.headline).foregroundStyle(.white)
                                        Text(ipa.bundle).font(.caption).foregroundStyle(Style.muted)
                                        Text("v\(ipa.version) • build \(ipa.build)").font(.caption2).foregroundStyle(Style.pink)
                                    }
                                    Spacer()
                                    Image(systemName: "chevron.right").foregroundStyle(Style.muted)
                                }
                            }
                        }.buttonStyle(.plain).contextMenu { Button(role: .destructive) { store.remove(ipa) } label: { Label("Delete", systemImage: "trash") } }
                    }
                    if items.isEmpty { ContentUnavailableView("No IPA packages", systemImage: "shippingbox", description: Text("Import an IPA from Files.")) }
                }.padding(20)
            }.background(Style.bg.ignoresSafeArea()).navigationBarHidden(true)
            .fileImporter(isPresented: $importing, allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data], allowsMultipleSelection: true) { result in
                switch result { case .success(let urls): store.importIPAs(urls); case .failure(let e): store.error = e.localizedDescription }
            }
            .fileImporter(isPresented: $importingFiles, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                switch result { case .success(let urls): store.importFiles(urls); case .failure(let e): store.error = e.localizedDescription }
            }
            .refreshable { store.reload() }
        }
    }
}
struct ImportedFiles: View {
    @EnvironmentObject var store: PlutoStore
    @State private var importing = false
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 13) {
                    Text("Files").font(.system(size: 26, weight: .bold, design: .rounded))
                    Button { importing = true } label: {
                        Label("Import from Files", systemImage: "folder.badge.plus").frame(maxWidth: .infinity)
                    }.buttonStyle(MainButton())
                    Text("General documents are stored locally. IPA files go to the IPA Library and provisioning profiles go to Signing Assets. Import P12/PFX files from the Assets tab so Pluto Sign can validate the password and store the identity in Keychain.")
                        .font(.footnote).foregroundStyle(Style.muted)
                    ForEach(store.documents) { file in
                        Panel {
                            HStack {
                                Image(systemName: "doc.fill").foregroundStyle(Style.pink)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(file.name).font(.subheadline.bold()).foregroundStyle(.white)
                                    Text("\(file.fileType) • \(ByteCountFormatter.string(fromByteCount: file.size, countStyle: .file))")
                                        .font(.caption).foregroundStyle(Style.muted)
                                }
                                Spacer()
                                ShareLink(item: file.url) { Image(systemName: "square.and.arrow.up") }
                                Button(role: .destructive) { store.removeDocument(file) } label: { Image(systemName: "trash") }
                            }
                        }
                    }
                    if store.documents.isEmpty {
                        ContentUnavailableView("No imported files", systemImage: "folder", description: Text("Use Import from Files to add documents."))
                    }
                }.padding(20)
            }.background(Style.bg.ignoresSafeArea()).navigationBarHidden(true)
                .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                    switch result { case .success(let urls): store.importFiles(urls); case .failure(let e): store.error = e.localizedDescription }
                }
                .refreshable { store.reload() }
        }
    }
}
struct IPADetail: View {
    let ipa: IPARecord
    @State private var browser = false
    @State private var search = false
    @State private var sync = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 13) {
                Text(ipa.app).font(.system(size: 27, weight: .bold))
                Text(ipa.bundle).font(.caption).foregroundStyle(Style.muted)
                Panel {
                    VStack(spacing: 8) {
                        line("Version", ipa.version); line("Build", ipa.build); line("File", ipa.name)
                        line("Size", ByteCountFormatter.string(fromByteCount: ipa.size, countStyle: .file))
                    }
                }
                button("Browse IPA contents", "folder.fill") { browser = true }
                button("Search files, dylibs, plists", "magnifyingglass") { search = true }
                button("Version synchronization", "arrow.triangle.2.circlepath") { sync = true }
                ShareLink(item: ipa.url) { Label("Share original IPA", systemImage: "square.and.arrow.up").frame(maxWidth: .infinity) }
                    .buttonStyle(.bordered).tint(Style.violet)
                Text("Version synchronization changes metadata only, not compiled code. Modified IPAs require authorized re-signing.").font(.footnote).foregroundStyle(Style.muted)
            }.padding(20)
        }.background(Style.bg.ignoresSafeArea()).navigationTitle("Package").navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $browser) { ArchiveBrowser(ipa: ipa, folder: "") }
            .sheet(isPresented: $search) { ArchiveSearch(ipa: ipa) }
            .sheet(isPresented: $sync) { VersionSync(ipa: ipa) }
    }
    func line(_ label: String, _ value: String) -> some View { HStack { Text(label).foregroundStyle(Style.muted); Spacer(); Text(value) }.font(.subheadline) }
    func button(_ title: String, _ icon: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) { Label(title, systemImage: icon).frame(maxWidth: .infinity) }.buttonStyle(.bordered).tint(Style.violet)
    }
}
struct ArchiveBrowser: View {
    let ipa: IPARecord
    let folder: String
    @State private var rows: [ArchiveRecord] = []
    @State private var error: String?
    var body: some View {
        NavigationStack {
            List {
                if !folder.isEmpty { NavigationLink(destination: ArchiveBrowser(ipa: ipa, folder: parent(folder))) { Label("Parent folder", systemImage: "arrow.up.left") } }
                ForEach(rows) { row in
                    if row.folder {
                        NavigationLink(destination: ArchiveBrowser(ipa: ipa, folder: row.path)) { Label(row.name, systemImage: "folder.fill").foregroundStyle(Style.pink) }
                    } else {
                        NavigationLink(destination: ArchivePreview(ipa: ipa, item: row)) {
                            VStack(alignment: .leading, spacing: 3) {
                                Label(row.name, systemImage: iconName(row.name)).foregroundStyle(.white)
                                Text(row.path).font(.caption2).foregroundStyle(Style.muted)
                            }
                        }
                    }
                }
            }.scrollContentBackground(.hidden).background(Style.bg)
                .navigationTitle(folder.isEmpty ? "IPA Contents" : URL(fileURLWithPath: folder).lastPathComponent)
                .navigationBarTitleDisplayMode(.inline).task { load() }
                .alert("Archive", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) { Button("OK") { error = nil } } message: { Text(error ?? "") }
        }.tint(Style.violet)
    }
    func load() { do { rows = try IPAService.list(ipa.url, folder: folder) } catch { self.error = error.localizedDescription } }
}
struct ArchiveSearch: View {
    let ipa: IPARecord
    @Environment(\.dismiss) var dismiss
    @State private var query = ""
    @State private var contentSearch = false
    @State private var rows: [ArchiveRecord] = []
    @State private var error: String?
    var body: some View {
        NavigationStack {
            VStack(spacing: 10) {
                TextField("Search .dylib, plist, framework…", text: $query).textInputAutocapitalization(.never).autocorrectionDisabled().padding(12).background(Style.card, in: RoundedRectangle(cornerRadius: 12)).onSubmit(run)
                Toggle("Search readable text contents", isOn: $contentSearch).tint(Style.violet)
                Button("Search entire IPA", action: run).buttonStyle(MainButton())
                List(rows) { row in
                    NavigationLink(destination: ArchivePreview(ipa: ipa, item: row)) {
                        VStack(alignment: .leading) { Text(row.name).foregroundStyle(.white); Text(row.path).font(.caption2).foregroundStyle(Style.muted) }
                    }.listRowBackground(Style.card)
                }.scrollContentBackground(.hidden)
            }.padding(15).background(Style.bg).navigationTitle("Archive Search").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .topBarLeading) { Button("Close") { dismiss() } } }
                .alert("Search", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) { Button("OK") { error = nil } } message: { Text(error ?? "") }
        }.tint(Style.violet)
    }
    func run() { do { rows = try IPAService.search(ipa.url, query: query, contents: contentSearch) } catch { self.error = error.localizedDescription } }
}
struct ArchivePreview: View {
    let ipa: IPARecord
    let item: ArchiveRecord
    @State private var text = ""
    @State private var error: String?
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text(item.name).font(.title3.bold())
                Text(item.path).font(.caption).foregroundStyle(Style.muted).textSelection(.enabled)
                if text.isEmpty { ContentUnavailableView("Binary or unsupported file", systemImage: "doc.text.magnifyingglass", description: Text("The preview displays small readable files. Binary files can be located but are not edited here.")) }
                else { Text(text).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(12).background(Style.card, in: RoundedRectangle(cornerRadius: 12)) }
            }.padding(18)
        }.background(Style.bg).navigationTitle("File Preview").navigationBarTitleDisplayMode(.inline)
            .task {
                let ext = URL(fileURLWithPath: item.name).pathExtension.lowercased()
                guard ["plist", "xml", "json", "txt", "strings", "md", "csv"].contains(ext) else { return }
                do {
                    let data = try IPAService.read(ipa.url, item.path)
                    if ext == "plist", let value = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                       let xml = try? PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0) {
                        text = String(data: xml, encoding: .utf8) ?? ""
                    } else { text = String(data: data, encoding: .utf8) ?? "" }
                } catch { self.error = error.localizedDescription }
            }
            .alert("Preview", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) { Button("OK") { error = nil } } message: { Text(error ?? "") }
    }
}
struct VersionSync: View {
    let ipa: IPARecord
    @EnvironmentObject var store: PlutoStore
    @Environment(\.dismiss) var dismiss
    @State private var version: String
    @State private var build: String
    @State private var rows: [BundleRecord] = []
    @State private var error: String?
    init(ipa: IPARecord) { self.ipa = ipa; _version = State(initialValue: ipa.version); _build = State(initialValue: ipa.build) }
    var body: some View {
        NavigationStack {
            Form {
                Section("Target metadata") { TextField("Version", text: $version); TextField("Build", text: $build) }
                Section("Embedded bundles") {
                    Button("Scan embedded versions") { scan() }
                    ForEach(rows) { row in
                        VStack(alignment: .leading, spacing: 3) {
                            Text("\(row.kind) • \(URL(fileURLWithPath: row.path).lastPathComponent)").font(.subheadline.bold())
                            Text(row.bundleID).font(.caption2).foregroundStyle(Style.muted)
                            Text("\(row.version) / \(row.build)").font(.caption).foregroundStyle(Style.muted)
                        }
                    }
                }
                Section {
                    Button("Create synchronized IPA") {
                        do {
                            let output = try IPAService.synchronize(ipa.url, version: version, build: build)
                            let meta = try IPAService.metadata(output)
                            guard meta.2 == version, meta.3 == build else {
                                try? FileManager.default.removeItem(at: output)
                                throw PlutoError.plist
                            }
                            let size = (try? FileManager.default.attributesOfItem(atPath: output.path)[.size] as? NSNumber)?.int64Value ?? 0
                            let record = IPARecord(name: output.lastPathComponent, path: output.path, app: meta.0, bundle: meta.1, version: meta.2, build: meta.3, size: size)
                            store.addSynchronizedIPA(record)
                            dismiss()
                        } catch { self.error = error.localizedDescription }
                    }.disabled(rows.isEmpty || version.isEmpty || build.isEmpty)
                } footer: {
                    Text("Updates version/build labels in embedded .app and .appex plists only. Frameworks and binaries remain unchanged. The signature is invalidated; use an authorized signing workflow.")
                }
            }.scrollContentBackground(.hidden).background(Style.bg).navigationTitle("Version Sync").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .topBarLeading) { Button("Close") { dismiss() } } }
                .task { scan() }
                .alert("Version Sync", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) { Button("OK") { error = nil } } message: { Text(error ?? "") }
        }.tint(Style.violet)
    }
    func scan() { do { rows = try IPAService.versions(ipa.url) } catch { self.error = error.localizedDescription } }
}
struct Assets: View {
    @EnvironmentObject var store: PlutoStore
    @State private var pickP12 = false
    @State private var pickProfile = false
    @State private var candidate: Data?
    @State private var candidateName = ""
    @State private var password = ""
    @State private var askPassword = false
    @State private var error: String?
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Certificates & Profiles").font(.system(size: 26, weight: .bold, design: .rounded))
                    Panel {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("IMPORT YOUR OWN SIGNING FILES").font(.caption.bold()).foregroundStyle(Style.pink)
                            Button { pickP12 = true } label: { Label("Import P12 / PFX", systemImage: "key.fill").frame(maxWidth: .infinity) }.buttonStyle(MainButton())
                            Button { pickProfile = true } label: { Label("Import .mobileprovision", systemImage: "person.text.rectangle").frame(maxWidth: .infinity) }.buttonStyle(.bordered).tint(Style.violet)
                        }
                    }
                    ForEach(["P12 / PFX", "Provisioning Profile"], id: \.self) { kind in
                        Text(kind.uppercased()).font(.caption.bold()).foregroundStyle(Style.muted)
                        ForEach(store.assets.filter { $0.kind == kind }) { asset in
                            Panel {
                                HStack {
                                    Image(systemName: kind == "P12 / PFX" ? "key.fill" : "doc.badge.gearshape").foregroundStyle(Style.pink)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(asset.name).font(.subheadline.bold())
                                        Text(kind == "P12 / PFX" ? "Stored in Keychain" : "Stored in app-private folder").font(.caption2).foregroundStyle(Style.muted)
                                        if let detail = asset.detail { Text(detail).font(.caption2).foregroundStyle(Style.muted).fixedSize(horizontal: false, vertical: true) }
                                    }
                                    Spacer()
                                    Button(role: .destructive) { store.remove(asset) } label: { Image(systemName: "trash") }
                                }
                            }
                        }
                    }
                    Text("P12/PFX bytes are stored in Keychain. The password is checked and discarded, never saved. Provisioning profiles are stored in app-private storage.")
                        .font(.footnote).foregroundStyle(Style.muted)
                }.padding(20)
            }.background(Style.bg).navigationBarHidden(true)
            .fileImporter(isPresented: $pickP12, allowedContentTypes: [UTType(filenameExtension: "p12") ?? .data, UTType(filenameExtension: "pfx") ?? .data]) { result in
                do {
                    let url = try result.get()
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    candidate = try Data(contentsOf: url)
                    candidateName = url.lastPathComponent
                    askPassword = true
                } catch { self.error = error.localizedDescription }
            }
            .fileImporter(isPresented: $pickProfile, allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data]) { result in
                do { store.importProfile(try result.get()) } catch { self.error = error.localizedDescription }
            }
            .sheet(isPresented: $askPassword) {
                NavigationStack {
                    Form {
                        SecureField("P12/PFX password", text: $password)
                        Text("The password is only used to validate the file; it is not stored.").font(.footnote).foregroundStyle(Style.muted)
                        Button("Validate and save to Keychain") {
                            do {
                                guard let data = candidate else { throw PlutoError.keychain(errSecParam) }
                                try store.importP12(data, name: candidateName, password: password)
                                candidate = nil; password = ""; askPassword = false
                            } catch { self.error = error.localizedDescription }
                        }.disabled(password.isEmpty)
                    }.navigationTitle("Unlock Certificate")
                        .toolbar { ToolbarItem(placement: .topBarLeading) { Button("Cancel") { askPassword = false; candidate = nil; password = "" } } }
                }.presentationDetents([.medium])
            }
            .alert("Signing Assets", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) { Button("OK") { error = nil } } message: { Text(error ?? "") }
        }.tint(Style.violet)
    }
}
struct SignPrep: View {
    @EnvironmentObject var store: PlutoStore

    @State private var ipaID = ""
    @State private var certID = ""
    @State private var profileID = ""

    @State private var pickIPA = false
    @State private var pickP12 = false
    @State private var pickProfile = false

    @State private var candidate: Data?
    @State private var candidateName = ""
    @State private var password = ""
    @State private var askPassword = false

    @State private var shareURL: URL?
    @State private var readiness = ""
    @State private var error: String?

    private var selectedIPA: IPARecord? {
        store.ipas.first { $0.id.uuidString == ipaID }
    }

    private var selectedCertificate: AssetRecord? {
        store.assets.first { $0.id.uuidString == certID && $0.kind == "P12 / PFX" }
    }

    private var selectedProfile: AssetRecord? {
        store.assets.first { $0.id.uuidString == profileID && $0.kind == "Provisioning Profile" }
    }

    var body: some View {
        NavigationStack {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 16) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Sign IPA")
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                            .foregroundStyle(.white)
                        Text("Choose your app package and bring your own Apple signing files.")
                            .font(.subheadline)
                            .foregroundStyle(Style.muted)
                    }

                    Panel {
                        VStack(alignment: .leading, spacing: 12) {
                            Label("1. SELECT OR IMPORT AN IPA", systemImage: "shippingbox.fill")
                                .font(.caption.bold())
                                .tracking(0.5)
                                .foregroundStyle(Style.pink)

                            selectionRow(
                                title: selectedIPA?.app ?? "No IPA selected",
                                detail: selectedIPA.map { "\($0.bundle) • v\($0.version) (\($0.build))" } ?? "Import an IPA package from Files",
                                icon: "app.dashed",
                                isReady: selectedIPA != nil
                            )

                            choose("IPA PACKAGE", value: $ipaID,
                                   items: store.ipas.map { ($0.id.uuidString, "\($0.app) • \($0.version)") })

                            Button {
                                pickIPA = true
                            } label: {
                                Label("Import IPA from Files", systemImage: "folder.badge.plus")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(MainButton())
                        }
                    }

                    Panel {
                        VStack(alignment: .leading, spacing: 12) {
                            Label("2. IMPORT YOUR OWN CERTIFICATE", systemImage: "key.fill")
                                .font(.caption.bold())
                                .tracking(0.5)
                                .foregroundStyle(Style.pink)

                            selectionRow(
                                title: selectedCertificate?.name ?? "No P12 / PFX selected",
                                detail: selectedCertificate == nil ? "Your private signing identity stays in this device's Keychain" : "Password validated • stored in Keychain",
                                icon: "key.horizontal.fill",
                                isReady: selectedCertificate != nil
                            )

                            choose("P12 / PFX IDENTITY", value: $certID,
                                   items: store.assets.filter { $0.kind == "P12 / PFX" }.map { ($0.id.uuidString, $0.name) })

                            Button {
                                pickP12 = true
                            } label: {
                                Label("Import my P12 / PFX certificate", systemImage: "key.badge.plus")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                            .tint(Style.violet)
                        }
                    }

                    Panel {
                        VStack(alignment: .leading, spacing: 12) {
                            Label("3. IMPORT YOUR PROVISIONING PROFILE", systemImage: "person.text.rectangle")
                                .font(.caption.bold())
                                .tracking(0.5)
                                .foregroundStyle(Style.pink)

                            selectionRow(
                                title: selectedProfile?.name ?? "No profile selected",
                                detail: selectedProfile == nil ? "Choose the profile issued for your app" : "Stored in Pluto Sign's private app storage",
                                icon: "doc.badge.gearshape",
                                isReady: selectedProfile != nil
                            )

                            choose("PROVISIONING PROFILE", value: $profileID,
                                   items: store.assets.filter { $0.kind == "Provisioning Profile" }.map { ($0.id.uuidString, $0.name) })

                            Button {
                                pickProfile = true
                            } label: {
                                Label("Import .mobileprovision", systemImage: "folder.badge.plus")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                            .tint(Style.violet)
                        }
                    }

                    Panel {
                        VStack(alignment: .leading, spacing: 11) {
                            Label("4. CHECK AND EXPORT", systemImage: "checkmark.shield.fill")
                                .font(.caption.bold())
                                .tracking(0.5)
                                .foregroundStyle(Style.pink)

                            checklistRow("IPA package selected", ready: selectedIPA != nil)
                            checklistRow("P12 / PFX imported", ready: selectedCertificate != nil)
                            checklistRow("Provisioning profile imported", ready: selectedProfile != nil)

                            Button {
                                guard let ipa = selectedIPA else {
                                    readiness = "Import or select an IPA package first."
                                    return
                                }
                                readiness = store.signingReadiness(
                                    ipa,
                                    certificate: selectedCertificate,
                                    profile: selectedProfile
                                )
                            } label: {
                                Label("Check signing inputs", systemImage: "checkmark.circle")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                            .tint(Style.violet)
                            .disabled(selectedIPA == nil)

                            Button {
                                do {
                                    guard let ipa = selectedIPA else { throw PlutoError.info }
                                    shareURL = try store.signingRequest(ipa, selectedCertificate, selectedProfile)
                                    readiness = "Signing handoff request created. Share the request with your authorized Mac signing workflow. The IPA has not been signed."
                                } catch {
                                    self.error = error.localizedDescription
                                }
                            } label: {
                                Label("Export signing handoff", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(MainButton())
                            .disabled(selectedIPA == nil || selectedCertificate == nil || selectedProfile == nil)

                            if !readiness.isEmpty {
                                Text(readiness)
                                    .font(.footnote)
                                    .foregroundStyle(Style.muted)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .padding(12)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Style.bg, in: RoundedRectangle(cornerRadius: 12))
                            }

                            if let shareURL {
                                ShareLink(item: shareURL) {
                                    Label("Share signing request JSON", systemImage: "doc.text")
                                }
                                .font(.subheadline.weight(.semibold))
                                .tint(Style.violet)
                            }

                            if let selectedIPA {
                                ShareLink(item: selectedIPA.url) {
                                    Label("Share original IPA", systemImage: "shippingbox")
                                }
                                .font(.subheadline.weight(.semibold))
                                .tint(Style.violet)
                            }
                        }
                    }

                    Panel {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("What happens on this screen?", systemImage: "info.circle.fill")
                                .font(.headline)
                                .foregroundStyle(Style.pink)
                            Text("Pluto Sign imports and protects your own P12/PFX identity, stores your provisioning profile, checks that the three inputs are present and exports a handoff request. It does not run Apple's codesign tool or claim that an IPA is signed.")
                                .font(.footnote)
                                .foregroundStyle(Style.muted)
                            Text("Actual signing must be completed on a Mac using Apple's authorized signing tools. The certificate and profile must match the app's bundle ID, entitlements and distribution method. Never share your P12 password or private key in a public repository.")
                                .font(.footnote)
                                .foregroundStyle(Style.muted)
                        }
                    }
                }
                .padding(18)
                .padding(.bottom, 25)
            }
            .background(Style.bg.ignoresSafeArea())
            .toolbar(.hidden, for: .navigationBar)
            .fileImporter(
                isPresented: $pickIPA,
                allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data],
                allowsMultipleSelection: true
            ) { result in
                switch result {
                case .success(let urls):
                    store.importIPAs(urls)
                    if let first = store.ipas.first { ipaID = first.id.uuidString }
                    readiness = ""
                case .failure(let error):
                    self.error = error.localizedDescription
                }
            }
            .fileImporter(
                isPresented: $pickP12,
                allowedContentTypes: [
                    UTType(filenameExtension: "p12") ?? .data,
                    UTType(filenameExtension: "pfx") ?? .data
                ]
            ) { result in
                do {
                    let url = try result.get()
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    candidate = try Data(contentsOf: url)
                    candidateName = url.lastPathComponent
                    askPassword = true
                } catch {
                    self.error = error.localizedDescription
                }
            }
            .fileImporter(
                isPresented: $pickProfile,
                allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data]
            ) { result in
                do {
                    store.importProfile(try result.get())
                    if let first = store.assets.first(where: { $0.kind == "Provisioning Profile" }) {
                        profileID = first.id.uuidString
                    }
                    readiness = ""
                } catch {
                    self.error = error.localizedDescription
                }
            }
            .sheet(isPresented: $askPassword) {
                NavigationStack {
                    Form {
                        Section("Certificate password") {
                            SecureField("P12 / PFX password", text: $password)
                            Text("The password is used only to validate the certificate file. Pluto Sign does not save the password.")
                                .font(.footnote)
                                .foregroundStyle(Style.muted)
                        }
                        Section {
                            Button("Validate and save to Keychain") {
                                do {
                                    guard let data = candidate else { throw PlutoError.keychain(errSecParam) }
                                    try store.importP12(data, name: candidateName, password: password)
                                    if let first = store.assets.first(where: { $0.kind == "P12 / PFX" }) {
                                        certID = first.id.uuidString
                                    }
                                    candidate = nil
                                    candidateName = ""
                                    password = ""
                                    askPassword = false
                                    readiness = ""
                                } catch {
                                    self.error = error.localizedDescription
                                }
                            }
                            .disabled(candidate == nil || password.isEmpty)
                        }
                    }
                    .navigationTitle("Import Certificate")
                    .toolbar {
                        ToolbarItem(placement: .topBarLeading) {
                            Button("Cancel") {
                                askPassword = false
                                candidate = nil
                                candidateName = ""
                                password = ""
                            }
                        }
                    }
                }
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
            }
            .alert("Sign IPA", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                Button("OK") { error = nil }
            } message: {
                Text(error ?? "")
            }
        }
        .tint(Style.violet)
    }

    private func selectionRow(title: String, detail: String, icon: String, isReady: Bool) -> some View {
        HStack(spacing: 11) {
            Image(systemName: icon)
                .font(.system(size: 19, weight: .semibold))
                .foregroundStyle(isReady ? Style.pink : Style.muted)
                .frame(width: 42, height: 42)
                .background(Style.violet.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                Text(detail)
                    .font(.caption2)
                    .foregroundStyle(Style.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Image(systemName: isReady ? "checkmark.circle.fill" : "circle.dashed")
                .foregroundStyle(isReady ? Style.violet : Style.muted)
        }
    }

    private func checklistRow(_ title: String, ready: Bool) -> some View {
        HStack(spacing: 9) {
            Image(systemName: ready ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(ready ? Style.violet : Style.muted)
            Text(title)
                .font(.subheadline)
                .foregroundStyle(ready ? .white : Style.muted)
            Spacer()
        }
    }

    private func choose(_ title: String, value: Binding<String>, items: [(String, String)]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption2.bold())
                .foregroundStyle(Style.muted)
            Picker(title, selection: value) {
                Text("Not selected").tag("")
                ForEach(items, id: \.0) { Text($0.1).tag($0.0) }
            }
            .pickerStyle(.menu)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(9)
            .background(Style.bg, in: RoundedRectangle(cornerRadius: 10))
        }
    }
}

func parent(_ path: String) -> String { path.split(separator: "/").dropLast().joined(separator: "/") }
func iconName(_ name: String) -> String {
    switch URL(fileURLWithPath: name).pathExtension.lowercased() {
    case "plist", "xml": return "list.bullet.rectangle"
    case "dylib": return "shippingbox"
    case "framework": return "shippingbox.fill"
    case "png", "jpg", "jpeg": return "photo"
    case "json": return "curlybraces"
    case "txt", "strings": return "doc.text"
    default: return "doc"
    }
}
