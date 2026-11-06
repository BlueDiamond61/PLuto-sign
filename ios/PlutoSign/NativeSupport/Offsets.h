#ifndef PLUTO_OFFSETS_H
#define PLUTO_OFFSETS_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Static offsets into an IPA file being inspected.
 * These are file positions only: never process-memory addresses,
 * runtime pointers, injection targets, or patch instructions.
 */
typedef struct PlutoFileOffset {
    uint64_t file_offset;
    uint64_t byte_count;
} PlutoFileOffset;

static inline bool PlutoFileOffsetIsInBounds(PlutoFileOffset item, uint64_t file_size) {
    return item.file_offset <= file_size &&
           item.byte_count <= file_size - item.file_offset;
}

#endif
