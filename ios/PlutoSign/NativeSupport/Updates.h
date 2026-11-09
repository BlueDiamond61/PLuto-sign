#ifndef PLUTO_SIGN_UPDATES_H
#define PLUTO_SIGN_UPDATES_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Pluto Sign update configuration.
 * This header contains product/update metadata only. It contains no
 * Roblox offsets, runtime memory addresses, pointers, or executor data.
 */

#define PLUTO_SIGN_PRODUCT_NAME "Pluto Sign"
#define PLUTO_SIGN_PRODUCT_IDENTIFIER "com.plutosign.app"

#define PLUTO_SIGN_RELEASES_URL \
    "https://www.plutosign.com/releases"
#define PLUTO_SIGN_LATEST_RELEASE_API \
    "https://api.github.com/repos/BlueDiamond61/PLuto-sign/releases/latest"
#define PLUTO_SIGN_RELEASE_NOTES_URL \
    "https://www.plutosign.com/releases"

/* Replace placeholders with the values from the published app release. */
#define PLUTO_SIGN_CURRENT_VERSION "1.0.1"
#define PLUTO_SIGN_CURRENT_BUILD "1"
#define PLUTO_SIGN_MINIMUM_SUPPORTED_VERSION "1.0.1"
#define PLUTO_SIGN_UPDATE_CHANNEL "stable"

/* Update behavior */
#define PLUTO_SIGN_UPDATE_CHECK_INTERVAL_HOURS 24u
#define PLUTO_SIGN_REQUEST_TIMEOUT_SECONDS 15u
#define PLUTO_SIGN_CHECK_ON_LAUNCH true
#define PLUTO_SIGN_ALLOW_PRERELEASES false

/*
 * Generate a UUID once per installation and store it in the platform
 * Keychain using this key. This is an app-installation ID, not Apple's
 * hardware UDID. UUID creation and Keychain persistence are implemented
 * by the app, not by this configuration header.
 */
#define PLUTO_SIGN_INSTALLATION_ID_KEY \
    "com.plutosign.installation-uuid"

/*
 * Describes a release manifest supplied by the update service.
 * The strings are metadata and must be validated by the app before use.
 */
typedef struct PlutoSignUpdateManifest {
    const char *version;
    const char *build;
    const char *minimum_supported_version;
    const char *download_url;
    const char *release_notes_url;
    const char *channel;
} PlutoSignUpdateManifest;

/*
 * Safe IPA archive file-range validation retained for the existing C
 * inspector. These are file positions, not process-memory offsets.
 */
typedef struct PlutoFileOffset {
    uint64_t file_offset;
    uint64_t byte_count;
} PlutoFileOffset;

static inline bool PlutoFileOffsetIsInBounds(
    PlutoFileOffset item,
    uint64_t file_size
) {
    return item.file_offset <= file_size &&
           item.byte_count <= file_size - item.file_offset;
}

#endif /* PLUTO_SIGN_UPDATES_H */
