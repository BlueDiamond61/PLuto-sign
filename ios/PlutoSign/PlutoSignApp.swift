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
    case archive, info, plist, missing, unsafe, large, keychain(OSStatus)
    var errorDescription: String? {
        switch self {
        case .archive: return "This IPA is not a readable ZIP archive."
        case .info: return "The main app Info.plist was not found."
        case .plist: return "The property list is invalid."
        case .missing: return "The archive item could not be found."
        case .unsafe: return "An unsafe archive path was blocked."
        case .large: return "This file is too large for the built-in preview."
        case .keychain(let status): return "Keychain error: \(status). Check the P12 password and try again."
        }
    }
}
enum PlutoStorage {
    static let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("PlutoSign")
    static let ipas = root.appendingPathComponent("IPAs")
    static let profiles = root.appendingPathComponent("Profiles")
    static let exports = root.appendingPathComponent("Exports")
    static let library = root.appendingPathComponent("library.json")
    static func prepare() throws {
        for url in [root, ipas, profiles, exports] {
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
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw PlutoError.keychain(status) }
    }
    static func remove(_ account: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.plutosign.signing-assets",
            kSecAttrAccount as String: account
        ] as CFDictionary)
    }
}
enum IPAService {
    static func safe(_ raw: String) -> String? {
        let value = raw.replacingOccurrences(of: "\\", with: "/")
        guard !value.isEmpty, !value.hasPrefix("/"), !value.contains("\0") else { return nil }
        let parts = value.split(separator: "/")
        guard !parts.isEmpty, !parts.contains(".."), !parts[0].contains(":") else { return nil }
        return parts.joined(separator: "/")
    }
    static func read(_ ipa: URL, _ path: String, max: Int = 2_000_000) throws -> Data {
        guard let archive = Archive(url: ipa, accessMode: .read), let entry = archive[path] else { throw PlutoError.missing }
        guard entry.type == .file else { throw PlutoError.plist }
        guard entry.uncompressedSize <= max else { throw PlutoError.large }
        var data = Data()
        _ = try archive.extract(entry) { data.append($0) }
        return data
    }
    static func metadata(_ ipa: URL) throws -> (String, String, String, String) {
        guard let archive = Archive(url: ipa, accessMode: .read) else { throw PlutoError.archive }
        let paths = archive.map(\.path).filter { $0.hasPrefix("Payload/") && $0.hasSuffix(".app/Info.plist") }
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
        let prefix = folder.isEmpty ? "" : ((safe(folder) ?? "") + "/")
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
                result[child] = ArchiveRecord(name: name, path: child, folder: isFolder, size: isFolder ? 0 : entry.uncompressedSize)
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
            if match { found.append(ArchiveRecord(name: URL(fileURLWithPath: path).lastPathComponent, path: path, folder: false, size: entry.uncompressedSize)) }
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
        guard !version.isEmpty, !build.isEmpty, let input = Archive(url: ipa, accessMode: .read) else { throw PlutoError.info }
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let tree = temp.appendingPathComponent("PayloadTree")
        try FileManager.default.createDirectory(at: tree, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }
        for entry in input {
            guard let path = safe(entry.path), entry.type != .symlink else { continue }
            let dest = tree.appendingPathComponent(path)
            if entry.type == .directory { try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true) }
            else {
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
        let outputURL = PlutoStorage.exports.appendingPathComponent("\(ipa.deletingPathExtension().lastPathComponent)-VersionSync-\(version).ipa")
        try? FileManager.default.removeItem(at: outputURL)
        guard let output = Archive(url: outputURL, accessMode: .create) else { throw PlutoError.archive }
        let files = FileManager.default.enumerator(at: tree, includingPropertiesForKeys: [.isRegularFileKey])
        while let file = files?.nextObject() as? URL {
            if (try? file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                try output.addEntry(with: String(file.path.dropFirst(tree.path.count + 1)), fileURL: file, compressionMethod: .deflate)
            }
        }
        _ = try metadata(outputURL)
        return outputURL
    }
}
@MainActor final class PlutoStore: ObservableObject {
    @Published var ipas: [IPARecord] = []
    @Published var assets: [AssetRecord] = []
    @Published var activity: [String] = []
    @Published var error: String?
    private struct Library: Codable { var ipas: [IPARecord] = []; var assets: [AssetRecord] = []; var activity: [String] = [] }
    init() {
        do {
            try PlutoStorage.prepare()
            if let data = try? Data(contentsOf: PlutoStorage.library), let lib = try? JSONDecoder().decode(Library.self, from: data) {
                ipas = lib.ipas.filter { FileManager.default.fileExists(atPath: $0.path) }
                assets = lib.assets
                activity = lib.activity
            }
        } catch { self.error = error.localizedDescription }
    }
    private func save() {
        do { try JSONEncoder().encode(Library(ipas: ipas, assets: assets, activity: activity)).write(to: PlutoStorage.library, options: .atomic) }
        catch { self.error = error.localizedDescription }
    }
    func log(_ value: String) { activity.insert(value, at: 0); activity = Array(activity.prefix(12)); save() }
    func importIPAs(_ urls: [URL]) {
        for url in urls {
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            do {
                let dest = PlutoStorage.unique(url.lastPathComponent, in: PlutoStorage.ipas)
                try FileManager.default.copyItem(at: url, to: dest)
                let info = try IPAService.metadata(dest)
                let size = (try? FileManager.default.attributesOfItem(atPath: dest.path)[.size] as? NSNumber)?.int64Value ?? 0
                ipas.insert(IPARecord(name: dest.lastPathComponent, path: dest.path, app: info.0, bundle: info.1, version: info.2, build: info.3, size: size), at: 0)
                log("Imported \(info.0)")
            } catch { error = error.localizedDescription }
        }
        save()
    }
    func importProfile(_ url: URL) {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        do {
            let dest = PlutoStorage.unique(url.lastPathComponent, in: PlutoStorage.profiles)
            try FileManager.default.copyItem(at: url, to: dest)
            assets.insert(AssetRecord(name: dest.lastPathComponent, kind: "Provisioning Profile", path: dest.path), at: 0)
            log("Imported provisioning profile")
        } catch { error = error.localizedDescription }
    }
    func importP12(_ data: Data, name: String, password: String) throws {
        try PlutoKeychain.validateP12(data, password: password)
        let account = UUID().uuidString
        try PlutoKeychain.save(data, account: account)
        assets.insert(AssetRecord(name: name, kind: "P12 / PFX", path: "keychain:" + account), at: 0)
        log("Stored certificate in Keychain")
    }
    func remove(_ asset: AssetRecord) {
        if asset.path.hasPrefix("keychain:") { PlutoKeychain.remove(String(asset.path.dropFirst(9))) }
        else { try? FileManager.default.removeItem(atPath: asset.path) }
        assets.removeAll { $0.id == asset.id }; log("Removed \(asset.name)")
    }
    func remove(_ ipa: IPARecord) {
        try? FileManager.default.removeItem(at: ipa.url)
        ipas.removeAll { $0.id == ipa.id }; log("Removed \(ipa.name)")
    }
    func signingRequest(_ ipa: IPARecord, _ cert: AssetRecord?, _ profile: AssetRecord?) throws -> URL {
        let json = try JSONSerialization.data(withJSONObject: [
            "ipa": ipa.name, "bundle_id": ipa.bundle, "version": ipa.version, "build": ipa.build,
            "certificate": cert?.name ?? "Not selected", "profile": profile?.name ?? "Not selected",
            "status": "Request only; actual signing must use an authorized signing workflow."
        ], options: [.prettyPrinted, .sortedKeys])
        let url = PlutoStorage.exports.appendingPathComponent("SigningRequest-\(UUID().uuidString.prefix(8)).json")
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
    var body: some View { content.padding(15).background(Style.card, in: RoundedRectangle(cornerRadius: 19)).overlay(RoundedRectangle(cornerRadius: 19).stroke(.white.opacity(0.06), lineWidth: 1)) }
}
struct MainButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.headline).foregroundStyle(.white).padding(13)
            .background(LinearGradient(colors: [Style.violet, Style.pink], startPoint: .leading, endPoint: .trailing), in: RoundedRectangle(cornerRadius: 14))
            .opacity(configuration.isPressed ? 0.8 : 1)
    }
}
struct PlutoTabs: View {
    @EnvironmentObject var store: PlutoStore
    var body: some View {
        TabView {
            Dashboard().tabItem { Label("Home", systemImage: "square.grid.2x2.fill") }
            Library().tabItem { Label("IPAs", systemImage: "shippingbox.fill") }
            Assets().tabItem { Label("Assets", systemImage: "key.fill") }
            SignPrep().tabItem { Label("Signing", systemImage: "signature") }
        }.tint(Style.violet)
        .alert("Pluto Sign", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
            Button("OK") { store.error = nil }
        } message: { Text(store.error ?? "") }
    }
}
struct Dashboard: View {
    @EnvironmentObject var store: PlutoStore
    @State private var importing = false
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack {
                        VStack(alignment: .leading, spacing: 0) {
                            Text("PLUTO").font(.system(size: 31, weight: .black, design: .rounded))
                            Text("SIGN").font(.system(size: 31, weight: .black, design: .rounded)).foregroundStyle(Style.violet)
                        }
                        Spacer()
                        Image(systemName: "sparkles.rectangle.stack.fill").font(.system(size: 38)).foregroundStyle(Style.pink)
                    }
                    Text("Your iOS package workspace").foregroundStyle(Style.muted)
                    HStack {
                        stat("IPA PACKAGES", "\(store.ipas.count)", "shippingbox")
                        stat("SIGNING ASSETS", "\(store.assets.count)", "key.horizontal")
                    }
                    Panel {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("QUICK ACTIONS").font(.caption.bold()).foregroundStyle(Style.pink)
                            Button { importing = true } label: { Label("Import IPA from Files", systemImage: "plus").frame(maxWidth: .infinity) }.buttonStyle(MainButton())
                        }
                    }
                    Panel {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("RECENT ACTIVITY").font(.caption.bold()).foregroundStyle(Style.muted)
                            if store.activity.isEmpty { Text("Imports and exports appear here.").font(.subheadline).foregroundStyle(Style.muted) }
                            ForEach(Array(store.activity.enumerated()), id: \.offset) { _, item in Label(item, systemImage: "checkmark.circle.fill").font(.subheadline) }
                        }
                    }
                    Text("Local IPA inspection and signing asset manager. Modified packages need authorized re-signing.").font(.footnote).foregroundStyle(Style.muted)
                }.padding(20)
            }.background(Style.bg.ignoresSafeArea()).navigationBarHidden(true)
            .fileImporter(isPresented: $importing, allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data], allowsMultipleSelection: true) { result in
                switch result { case .success(let urls): store.importIPAs(urls); case .failure(let e): store.error = e.localizedDescription }
            }
        }
    }
    func stat(_ title: String, _ value: String, _ icon: String) -> some View {
        Panel { VStack(alignment: .leading, spacing: 8) { Image(systemName: icon).foregroundStyle(Style.pink); Text(value).font(.system(size: 28, weight: .bold)); Text(title).font(.caption2.bold()).foregroundStyle(Style.muted) }.frame(maxWidth: .infinity, alignment: .leading) }
    }
}
struct Library: View {
    @EnvironmentObject var store: PlutoStore
    @State private var importing = false
    @State private var query = ""
    var items: [IPARecord] { store.ipas.filter { query.isEmpty || "\($0.app) \($0.bundle) \($0.version) \($0.name)".localizedCaseInsensitiveContains(query) } }
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 13) {
                    Text("IPA Library").font(.system(size: 26, weight: .bold, design: .rounded))
                    Button { importing = true } label: { Label("Import IPA", systemImage: "plus").frame(maxWidth: .infinity) }.buttonStyle(MainButton())
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
                            let size = (try? FileManager.default.attributesOfItem(atPath: output.path)[.size] as? NSNumber)?.int64Value ?? 0
                            store.ipas.insert(IPARecord(name: output.lastPathComponent, path: output.path, app: meta.0, bundle: meta.1, version: meta.2, build: meta.3, size: size), at: 0)
                            store.log("Created metadata-synchronized IPA")
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
                    Text("Signing Assets").font(.system(size: 26, weight: .bold, design: .rounded))
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
                                    VStack(alignment: .leading) {
                                        Text(asset.name).font(.subheadline.bold())
                                        Text(kind == "P12 / PFX" ? "Stored in Keychain" : "Stored in app-private folder").font(.caption2).foregroundStyle(Style.muted)
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
    @State private var shareURL: URL?
    @State private var error: String?
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Signing Preparation").font(.system(size: 26, weight: .bold, design: .rounded))
                    Panel {
                        VStack(alignment: .leading, spacing: 10) {
                            choose("IPA", value: $ipaID, items: store.ipas.map { ($0.id.uuidString, "\($0.app) • \($0.version)") })
                            choose("P12 / PFX", value: $certID, items: store.assets.filter { $0.kind == "P12 / PFX" }.map { ($0.id.uuidString, $0.name) })
                            choose("Profile", value: $profileID, items: store.assets.filter { $0.kind == "Provisioning Profile" }.map { ($0.id.uuidString, $0.name) })
                            Button {
                                do {
                                    guard let ipa = store.ipas.first(where: { $0.id.uuidString == ipaID }) else { throw PlutoError.info }
                                    shareURL = try store.signingRequest(ipa, store.assets.first { $0.id.uuidString == certID }, store.assets.first { $0.id.uuidString == profileID })
                                } catch { self.error = error.localizedDescription }
                            } label: { Label("Export signing request", systemImage: "square.and.arrow.up").frame(maxWidth: .infinity) }.buttonStyle(MainButton()).disabled(ipaID.isEmpty)
                            if let shareURL { ShareLink(item: shareURL) { Label("Share request JSON", systemImage: "shareplay") } }
                        }
                    }
                    Panel {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Signing limitations", systemImage: "lock.shield.fill").font(.headline).foregroundStyle(Style.pink)
                            Text("This iOS app imports and protects your own signing files, then exports a signing request. It does not sign or install arbitrary IPAs. Actual signing needs an authorized Apple signing workflow.")
                                .font(.footnote).foregroundStyle(Style.muted)
                            Link("Open InstallOnAir", destination: URL(string: "https://www.installonair.com/")!)
                            Text("InstallOnAir hosts an already-signed IPA. It does not sign it.").font(.caption).foregroundStyle(Style.muted)
                        }
                    }
                }.padding(20)
            }.background(Style.bg).navigationBarHidden(true)
            .alert("Signing", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) { Button("OK") { error = nil } } message: { Text(error ?? "") }
        }
    }
    func choose(_ title: String, value: Binding<String>, items: [(String, String)]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title.uppercased()).font(.caption2.bold()).foregroundStyle(Style.muted)
            Picker(title, selection: value) {
                Text("Not selected").tag("")
                ForEach(items, id: \.0) { Text($0.1).tag($0.0) }
            }.pickerStyle(.menu).frame(maxWidth: .infinity, alignment: .leading).padding(8).background(Style.bg, in: RoundedRectangle(cornerRadius: 10))
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
