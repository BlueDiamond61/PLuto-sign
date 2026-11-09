import SwiftUI
import Foundation

private struct GitHubRelease: Decodable {
    let tag_name: String
    let name: String?
    let html_url: String
    let prerelease: Bool
    let draft: Bool
}

private struct PlutoAvailableUpdate {
    let version: String
    let title: String
    let releaseURL: URL
}

struct PlutoUpdatePrompt: ViewModifier {
    @Environment(\.openURL) private var openURL
    @State private var update: PlutoAvailableUpdate?
    @State private var showingUpdate = false
    @State private var hasChecked = false

    func body(content: Content) -> some View {
        content
            .task {
                guard !hasChecked else { return }
                hasChecked = true
                await checkForUpdate()
            }
            .alert("Pluto Sign update available", isPresented: $showingUpdate, presenting: update) { item in
                Button("View update") {
                    openURL(item.releaseURL)
                }
                Button("Later", role: .cancel) { }
            } message: { item in
                Text("\(item.title) (\(item.version)) is available. Open the official release page to review the update.")
            }
    }

    @MainActor
    private func checkForUpdate() async {
        guard let current = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
              let endpoint = URL(string: "https://api.github.com/repos/BlueDiamond61/PLuto-sign/releases/latest") else {
            return
        }

        var request = URLRequest(url: endpoint)
        request.timeoutInterval = 12
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("PlutoSign-iOS", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  (200...299).contains(http.statusCode) else { return }
            let release = try JSONDecoder().decode(GitHubRelease.self, from: data)
            guard !release.draft, !release.prerelease,
                  let releaseURL = URL(string: release.html_url),
                  isNewer(release.tag_name, than: current) else { return }

            update = PlutoAvailableUpdate(
                version: release.tag_name,
                title: release.name?.isEmpty == false ? release.name! : "A newer version",
                releaseURL: releaseURL
            )
            showingUpdate = true
        } catch {
            // Offline or malformed release data must never block app startup.
        }
    }

    private func isNewer(_ remote: String, than local: String) -> Bool {
        func components(_ value: String) -> [Int]? {
            let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "v", with: "")
            let core = normalized.split(separator: "-", maxSplits: 1).first.map(String.init) ?? normalized
            let parts = core.split(separator: ".", omittingEmptySubsequences: false)
            guard !parts.isEmpty else { return nil }
            let numbers = parts.compactMap { Int($0) }
            guard numbers.count == parts.count else { return nil }
            return numbers
        }

        guard let lhs = components(remote), let rhs = components(local) else { return false }
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            if left != right { return left > right }
        }
        return false
    }
}
