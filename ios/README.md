Native SwiftUI iOS companion for Pluto Sign. Includes IPA import and metadata inspection, archive browsing, archive-wide search for dylib/plist/framework paths, embedded bundle version audit, metadata-only version synchronization, P12/PFX import protected in iOS Keychain, provisioning profile inventory, and signing request export.

The app does not sign or install arbitrary IPAs. Actual signing must use an authorized Apple workflow. InstallOnAir hosts an already-signed device IPA; it does not sign it. A simulator build artifact is not installable on a physical iPhone.

Open ios/PlutoSign.xcodeproj in Xcode on macOS. The GitHub Actions workflow checks compilation on an iOS Simulator using a hosted macOS runner. Set a unique bundle ID and a legitimate Apple signing team to make a device build.
