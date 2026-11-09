# C's — Native examples

This folder is compiled into the Pluto Sign iOS target and contains small, safe native helpers:

- `PLTByteValidation.c/.h`: overflow-safe validation of a byte range inside a file.
- `PLTArchiveSummary.cpp/.hpp`: basic IPA/ZIP filename and extension helpers.
- `PlutoNativeInfo.m/.h`: Objective-C helpers for reading public app and operating-system version information.

These examples operate on local file metadata and public system information. They do not inspect or modify another process, patch memory, inject code, or bypass platform security.

## Languages

- C: `.c` and `.h`
- C++: `.cpp` and `.hpp`
- Objective-C: `.m` and Objective-C headers
- Swift remains the main SwiftUI application language.
