//
//  RootlessJB.h
//  Clutch
//
//  Rootless jailbreak compatibility layer
//  For jailbreaks like palera1n, Dopamine that use /var/jb as root
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Check if running on a rootless jailbreak
static inline BOOL isRootlessJailbreak(void) {
    static BOOL checked = NO;
    static BOOL isRootless = NO;

    if (!checked) {
        // Check for /var/jb symlink/directory which indicates rootless jailbreak
        isRootless = [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"];
        checked = YES;
    }

    return isRootless;
}

// Get the jailbreak root prefix
// Returns @"/var/jb" for rootless, @"" for rootful jailbreaks
static inline NSString *jbRoot(void) {
    return isRootlessJailbreak() ? @"/var/jb" : @"";
}

// Prepend jailbreak root to a path if needed
// For rootless: /var/tmp -> /var/jb/var/tmp
// For rootful: /var/tmp -> /var/tmp (unchanged)
static inline NSString *jbRootPath(NSString *path) {
    if (isRootlessJailbreak() && path.length > 0) {
        // Don't double-prefix if already prefixed
        if ([path hasPrefix:@"/var/jb"]) {
            return path;
        }
        return [@"/var/jb" stringByAppendingString:path];
    }
    return path;
}

// Convert a potentially rootless path back to the canonical form
// For rootless: /var/jb/var/tmp -> /var/tmp (strips prefix)
// For rootful: /var/tmp -> /var/tmp (unchanged)
static inline NSString *stripJBRoot(NSString *path) {
    if ([path hasPrefix:@"/var/jb"]) {
        return [path substringFromIndex:7]; // strlen("/var/jb") = 7
    }
    return path;
}

NS_ASSUME_NONNULL_END
