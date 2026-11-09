#include "PLTArchiveSummary.hpp"
#include <algorithm>
#include <cctype>

namespace {
std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
}

namespace PlutoNative {
std::string archiveExtension(const std::string& filename) {
    const auto dot = filename.find_last_of('.');
    if (dot == std::string::npos || dot + 1 >= filename.size()) return {};
    return lowercase(filename.substr(dot));
}

bool isSupportedArchiveName(const std::string& filename) {
    const auto extension = archiveExtension(filename);
    return extension == ".ipa" || extension == ".zip";
}
}
