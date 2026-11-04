# Pluto Sign iOS

Native SwiftUI project for the Pluto Sign workspace.

## App areas
- **Home:** refreshed dashboard, library counts, quick actions, profile page and recent activity.
- **IPAs:** multi-select IPA import, metadata inspection, archive browsing/search, version audit and metadata synchronization.
- **Files:** general local document imports with share and delete actions. IPA and provisioning profile files route to their dedicated sections.
- **Assets:** import your own P12/PFX files after password validation; store the P12 data in iOS Keychain. Import provisioning profiles into app-private storage.
- **Signing:** select an IPA, certificate identity and profile; check that inputs are present; export a signing request.

## Build
Open `ios/PlutoSign.xcodeproj` in Xcode on macOS. GitHub Actions builds an iOS Simulator target on a hosted macOS runner. The simulator artifact is not installable on a physical iPhone.

## Signing limitations
The iOS app does not re-sign or install arbitrary IPA packages. A local input check is not proof that a P12 identity and provisioning profile are compatible. Actual signing must happen in an authorized Apple workflow that validates bundle ID, profile expiry, entitlements, device/distribution method, certificate pairing and final signature. Metadata edits invalidate the original IPA signature.

The `.mobileconfig` file installs only a removable Web Clip shortcut to the Pluto Sign homepage. It does not install the native app, certificates, VPN or management settings.

Do not upload P12/PFX files, passwords, private keys or provisioning profiles to this public repository.