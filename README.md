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


## Native language support

The iOS target compiles Swift, C, C++, and Objective-C. The `ios/PlutoSign/C's` folder contains small local-file and app-metadata examples. See its README for the file list and purpose.

The Home tab links to the removable Home Screen Web Clip profile and the latest GitHub release. On launch, the app checks GitHub's latest stable release and displays an update prompt when its version is newer. The prompt opens the official release page; it does not silently install or replace the app.

## Admin authentication

Admin sign-in is not enabled until a server-side HTTPS authentication endpoint is configured. Do not put an admin token in the app or repository, even in obfuscated form. See `ios/ADMIN_AUTH_SETUP.md` for the required server-side design.

## Reliability and archive safeguards

- Archive paths are normalized and traversal/drive-style paths are rejected before extraction or preview.
- Text previews enforce declared and streamed size limits to avoid loading oversized archive entries into memory.
- Version synchronization accepts a constrained version/build format, rejects symbolic links and oversized archives, writes to a temporary archive, verifies the result, and chooses a new export name instead of overwriting an earlier copy.
- Library reload checks that locally stored files and Keychain identities still exist; corrupt library data is reported without replacing the original file.
- Delete actions only remove library records after the corresponding file or Keychain item was successfully removed.
- P12/PFX imports are size-limited and password-validated locally. Provisioning-profile imports are size-limited and stored locally; this is not a full profile-signature or compatibility validation.
- Signing handoff JSON contains filenames and package metadata only. It never exports certificate bytes, passwords, or private keys, and it is not a signed IPA.
