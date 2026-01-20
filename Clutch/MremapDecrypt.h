//
//  MremapDecrypt.h
//  Clutch
//
//  Modern file-based decryption using mremap_encrypted syscall.
//  This approach works on iOS 12+ where task_for_pid is restricted.
//
//  Based on techniques from flexdecrypt and fouldecrypt.
//

#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>

NS_ASSUME_NONNULL_BEGIN

// mremap_encrypted - Apple's private syscall for decrypting memory pages
// This is exposed by libc but not documented
extern int mremap_encrypted(void *addr, size_t len, uint32_t cryptid, uint32_t cputype, uint32_t cpusubtype);

@interface MremapDecrypt : NSObject

// Decrypt a Mach-O binary file using mremap_encrypted
// Returns YES on success, NO on failure
+ (BOOL)decryptBinary:(NSString *)inputPath
             toOutput:(NSString *)outputPath
                error:(NSError *_Nullable *_Nullable)error;

// Check if mremap_encrypted is available on this system
+ (BOOL)isAvailable;

// Allow invalid codesigned memory by self-debugging
// Required before mremap_encrypted will work
+ (BOOL)allowInvalidCodesignedMemory;

@end

NS_ASSUME_NONNULL_END
