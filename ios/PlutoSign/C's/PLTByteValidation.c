#include "PLTByteValidation.h"

bool PLTIsByteRangeValid(uint64_t offset, uint64_t length, uint64_t fileSize) {
    return offset <= fileSize && length <= fileSize - offset;
}
