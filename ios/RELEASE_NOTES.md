# Pluto Sign iOS — workspace update

The app now has five main tabs: Home, View IPAs, Files, Cert Import and Sign IPA. The dashboard and shared panels use the Pluto Sign purple theme, and a custom AppIcon asset catalog has been added.

## Maintenance patch
- Added `docs/content.json` as the versioned source for web workspace labels and project links.
- Removed the stale hard-coded Roblox package version and size from the import prompt; the workspace now asks users to select an IPA they already have.
- Fixed IPA removal so the visible library is updated only after a saved browser copy is successfully deleted.
- Added pre-read size checks for P12/PFX imports in the native app.
- Prevented P12/PFX files from being copied into the general Documents library; they must use the password-checked Keychain import flow.
- Changed certificate Keychain accessibility to require the device to be unlocked.

## Included
- Multi-select IPA import and IPA metadata list.
- Per-IPA archive browser and search.
- General document import, sharing and deletion.
- Own P12/PFX import with local password validation and iOS Keychain storage.
- Own provisioning-profile import and private app storage.
- Sign IPA preparation screen with direct IPA, P12/PFX and profile imports.
- Input presence checklist, signing-readiness messaging and signing handoff request export.
- Embedded app/extension version audit and metadata-only synchronization.
- Refreshed public homepage and branded Web Clip configuration profile icon.

## Signing and installation limits
The iOS app organizes and checks signing inputs and exports a handoff request; it does not run Apple's macOS code-signing tools and it does not claim to sign an IPA. Input presence is not proof of compatibility. An authorized macOS signing workflow must validate the bundle ID, entitlements, profile expiry, distribution method, certificate pairing and final signature.

The `.mobileconfig` installs only a removable website shortcut and icon. It does not install the native app, certificates or device management.

The automated GitHub Actions artifact is an iOS Simulator build, not an installable device IPA. Physical-device distribution requires a properly signed device build through an authorized Apple workflow.

No private keys, P12/PFX files, passwords, or provisioning profiles are included in this repository.
