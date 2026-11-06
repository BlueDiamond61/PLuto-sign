# Pluto Sign iOS

Native SwiftUI project for the Pluto Sign workspace.

## App tabs

- **Home:** dashboard with library counts and quick actions.
- **View IPAs:** import one or more IPA files, inspect metadata, browse package contents, search files and run metadata-only version synchronization.
- **Files:** import and organize documents locally, share or remove files. IPA and provisioning-profile imports are routed to their respective sections.
- **Cert Import:** bring your own P12/PFX certificate and provisioning profile. P12/PFX password validation is performed locally; the password is not saved and the P12/PFX file is stored in iOS Keychain.
- **Sign IPA:** import/select an IPA, select the certificate and provisioning profile, check that inputs are present, and export a signing handoff request. The screen can also import the required files without leaving the tab.

## Signing limitations

The iOS app prepares a signing handoff; it does not execute Apple's macOS `codesign` tool and does not claim to have signed the IPA. A selection check only confirms that inputs are present, not that they are compatible. Actual signing must use an authorized Apple workflow on macOS and validate the certificate, provisioning profile, bundle ID, entitlements, expiry and distribution method.

The `.mobileconfig` installs only a removable Web Clip shortcut to the public homepage. It includes a custom PNG icon so iOS does not fall back to the plain white/gray square.

## Build

Open `ios/PlutoSign.xcodeproj` in Xcode on macOS. The project includes an AppIcon asset catalog. GitHub Actions builds an iOS Simulator target on a hosted macOS runner. The simulator artifact is not installable on a physical iPhone.

Do not commit P12/PFX files, passwords, private keys or provisioning profiles to this public repository.


## Native C and C++ support

The Xcode target includes a small native support folder with both C and C++ translation units.
- `NativeSupport/Offsets.h` describes **static IPA file offsets only** and provides a file-bounds check. It does not define live process-memory addresses or patch targets.
- `NativeSupport/Addresses.h` contains public Pluto Sign web URLs.
- `FileOffsetValidation.c` and `PlutoFileInspector.cpp` demonstrate C and C++ compilation in the iOS target.

The Home tab links directly to the removable Home Screen Web Clip profile and the latest GitHub release. The update link opens the release page; it does not silently install or replace the app.
