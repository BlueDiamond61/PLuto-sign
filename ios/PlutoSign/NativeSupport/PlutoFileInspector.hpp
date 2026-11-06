#ifndef PLUTO_FILE_INSPECTOR_HPP
#define PLUTO_FILE_INSPECTOR_HPP

#include <cstdint>
#include "Offsets.h"

namespace PlutoNative {
struct FileRange {
    std::uint64_t offset;
    std::uint64_t size;

    bool isValid(std::uint64_t fileSize) const noexcept {
        const PlutoFileOffset item{offset, size};
        return PlutoFileOffsetIsInBounds(item, fileSize);
    }
};
}

#endif
