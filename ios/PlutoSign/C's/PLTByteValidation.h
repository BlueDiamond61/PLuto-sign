#ifndef PLT_BYTE_VALIDATION_H
#define PLT_BYTE_VALIDATION_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Validates a byte range inside a file without overflowing. */
bool PLTIsByteRangeValid(uint64_t offset, uint64_t length, uint64_t fileSize);

#ifdef __cplusplus
}
#endif

#endif
