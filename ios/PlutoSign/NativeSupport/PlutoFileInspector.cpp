#include "PlutoFileInspector.hpp"

/*
 * IPA archive inspection helpers.
 * These functions validate ranges within an archive file only; they do not
 * read or address another process's memory.
 */
namespace PlutoNative {
bool isReadableRange(const FileRange& range, std::uint64_t fileSize) noexcept {
    return range.isValid(fileSize);
}
}
