#include "PlutoFileInspector.hpp"

/* C++ translation unit included to keep native C++ support enabled. */
namespace PlutoNative {
bool isReadableRange(const FileRange& range, std::uint64_t fileSize) noexcept {
    return range.isValid(fileSize);
}
}
