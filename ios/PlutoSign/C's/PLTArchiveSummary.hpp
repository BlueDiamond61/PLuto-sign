#ifndef PLT_ARCHIVE_SUMMARY_HPP
#define PLT_ARCHIVE_SUMMARY_HPP

#include <string>

namespace PlutoNative {
    bool isSupportedArchiveName(const std::string& filename);
    std::string archiveExtension(const std::string& filename);
}

#endif
