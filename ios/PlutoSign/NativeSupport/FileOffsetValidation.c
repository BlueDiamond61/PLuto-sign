#include "Offsets.h"

/* Bounds-check a static file range before reading from an IPA archive entry. */
bool PlutoValidateFileRange(uint64_t file_offset, uint64_t byte_count, uint64_t file_size) {
    const PlutoFileOffset item = { file_offset, byte_count };
    return PlutoFileOffsetIsInBounds(item, file_size);
}
