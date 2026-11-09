#import "PlutoNativeInfo.h"

@implementation PlutoNativeInfo

+ (NSString *)operatingSystemDescription {
    return [NSProcessInfo processInfo].operatingSystemVersionString;
}

+ (NSString *)applicationVersion {
    NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    return version.length > 0 ? version : @"Unknown";
}

@end
