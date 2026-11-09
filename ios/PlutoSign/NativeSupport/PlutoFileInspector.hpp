#ifndef PLUTO_FILE_INSPECTOR_HPP
#define PLUTO_FILE_INSPECTOR_HPP

#include <cstdint>
#include "Updates.h"

namespace PlutoNative {

/* A byte range within an IPA/archive file, never a process-memory address. */
struct FileRange {
    std::uint64_t offset;
    std::uint64_t size;

    bool isValid(std::uint64_t fileSize) const noexcept {
        const PlutoFileOffset item{offset, size};
        return PlutoFileOffsetIsInBounds(item, fileSize);
    }
};

/* Returns true only when the complete range fits inside the archive file. */
bool isReadableRange(const FileRange& range, std::uint64_t fileSize) noexcept;

} // namespace PlutoNative

#endif /* PLUTO_FILE_INSPECTOR_HPP */
