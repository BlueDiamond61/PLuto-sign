import SwiftUI

@main
struct PlutoSignApp: App {
    @StateObject private var store = PlutoStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .preferredColorScheme(.dark)
        }
    }
}
