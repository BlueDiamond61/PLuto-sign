# Pluto Sign iOS — workspace update

The SwiftUI workspace now includes a redesigned dashboard and five main areas: Home, IPAs, Files, Assets and Signing.

## Included
- Multi-select IPA import through the iOS Files picker.
- IPA metadata display and local package library.
- Archive browser and search for file paths, dylibs, frameworks, property lists and readable text.
- Separate Files area for general local documents with share and delete actions.
- P12/PFX import with password validation and Keychain storage.
- Provisioning profile import and inventory.
- Signing input selection, basic local presence checks and signing request export.
- Embedded version audit and metadata-only synchronization for app and extension property lists.
- Library reload on app launch and pull-to-refresh.
- Pluto Sign Home Screen profile download page.

## Signing and installation limits
The iOS app organizes signing inputs and prepares a request; it does not sign or install arbitrary IPAs. A local selection check does not prove certificate/profile compatibility. The authorized macOS signing workflow must validate bundle ID, entitlements, distribution method, certificate pairing and signature. Modified package metadata invalidates its original signature.

The .mobileconfig profile adds only a removable Web Clip shortcut to the public Pluto Sign homepage. It does not install the native app, certificates or device management.

The automated GitHub Actions artifact is an iOS Simulator build, not an installable device IPA. Physical-device distribution requires a properly signed device build through an authorized Apple workflow.

No private keys, P12/PFX files, passwords, or provisioning profiles are included in this repository.