# Pluto Sign — SwiftUI iOS project

Pluto Sign is a native SwiftUI starter project for managing IPA packages and local signing assets. It uses a dark black/purple visual style and is organized into separate models, services, and views.

## Open in Visual Studio Code

1. Extract `PlutoSign-VSCode.zip`.
2. In Visual Studio Code, choose **File → Open Folder** and select the extracted `PlutoSign` folder.
3. Edit the Swift files in `PlutoSign/`.

VS Code is being used here as the code editor. **Building and signing an iOS app still requires Xcode running on macOS** (locally or through a trusted cloud macOS build service). Windows by itself cannot compile this SwiftUI project into an iOS IPA.

## Build on a Mac

1. Open `PlutoSign.xcodeproj` in Xcode.
2. Let Xcode resolve the Swift Package Manager dependency `ZIPFoundation` (version 0.9.20 or compatible 0.9.x release).
3. Select the `Pluto Sign` target and a simulator or registered test device.
4. Set your Apple Developer Team under **Signing & Capabilities** if you are building for a physical device.
5. Build and run. For an archive, select **Product → Archive** and follow Apple's supported distribution workflow.

## Included features

- SwiftUI dashboard and bottom navigation.
- Import `.ipa` files from Files and store them in the app's local Application Support directory.
- Read IPA `Info.plist` metadata from the ZIP archive: app name, bundle identifier, version and build number.
- Attempt to extract and display the app icon.
- Search, select and delete imported IPA packages.
- Import `.p12` certificate files, validate them with Security.framework, and store the P12 encrypted with AES-GCM using a key held in Keychain. The P12 password is not saved.
- Import `.mobileprovision` files and parse basic embedded plist metadata where the CMS payload is readable. Parsing metadata is not a signature or compatibility verification.
- Choose an IPA, certificate and profile to prepare a JSON signing-request manifest.
- Distribution information for TestFlight, Ad Hoc and App Store workflows.

## Important limits

- The signing screen **does not re-sign the IPA**. It exports a request manifest. Actual signing must be completed by an authorized macOS signing workflow using compatible credentials and a provisioning profile.
- The app does not include a backend service. It does not upload certificates or private keys.
- A certificate/profile being imported does not mean they match the selected IPA. Bundle ID, entitlements, device registration, certificate validity and profile validity must be checked by the signing host.
- An ordinary iOS app cannot directly install arbitrary IPA files through a public iOS API. Use Apple's supported distribution methods, such as TestFlight, Ad Hoc distribution to registered devices, or App Store distribution.
- This is a source project scaffold. It has had Swift syntax parsing and project-file checks in this environment, but it has **not** been built in Xcode or tested on an iPhone. Resolve any Xcode SDK or signing issues in the macOS build environment.

## Project layout

```text
PlutoSign/
├── PlutoSign.xcodeproj/
├── PlutoSign/
│   ├── PlutoSignApp.swift
│   ├── Models/
│   ├── Services/
│   └── Views/
└── README.md
```

## Dependency

- [ZIPFoundation](https://github.com/weichsel/ZIPFoundation) — MIT-licensed Swift package used to read IPA ZIP archives.

## Native iOS version

The native SwiftUI project is in [ios/](ios/). It includes IPA import, metadata inspection, archive browsing/search, version audit and metadata synchronization, P12/PFX import into Keychain, provisioning profile inventory, and signing-request export.

To check the iOS project compilation, open [GitHub Actions](https://github.com/BlueDiamond61/PLuto-sign/actions) and run **Pluto Sign iOS Build Check**. Its output is an iOS Simulator artifact, not an installable iPhone IPA.

**Device distribution:** a physical-device IPA must be signed through an authorized Apple workflow with a matching provisioning profile before uploading it to [InstallOnAir](https://www.installonair.com/). InstallOnAir hosts a signed IPA; it does not sign it or remove Apple's device authorization requirements.

## iPhone Home Screen profile

The iOS app homepage has a **Download Home Screen Profile** action. The profile adds only a removable Web Clip shortcut to the project homepage. It does not install certificates, configure trust, enroll MDM, or make unsigned IPA packages installable.

The public profile landing page is deployed from `docs/` through GitHub Pages. On iPhone, open it in Safari, tap the download button, tap **Allow**, then open Settings → **Profile Downloaded** to review and install. iOS removes a downloaded-but-uninstalled profile after a short time, so complete the review promptly.

### One-time Pages setup

The GitHub connection cannot enable Pages settings for you. In this repository, open **Settings → Pages**, set **Build and deployment → Source** to **GitHub Actions**, then open **Actions** and rerun **Deploy Pluto Sign homepage**. After that deployment completes, the profile link in the iOS Home tab will be live.
