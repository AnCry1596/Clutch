//
//  MremapDumper.m
//  Clutch
//
//  Modern file-based dumper using mremap_encrypted syscall.
//

#import "MremapDumper.h"
#import "MremapDecrypt.h"
#import "Device.h"
#import "ClutchPrint.h"
#import <mach-o/fat.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <fcntl.h>

@implementation MremapDumper

+ (BOOL)isSupported {
    return [MremapDecrypt isAvailable];
}

- (cpu_type_t)supportedCPUType {
    // MremapDumper supports arm64 (and arm64e)
    return CPU_TYPE_ARM64;
}

- (ArchCompatibility)compatibilityMode {
    // Check if this dumper can handle the binary
    if (self.thinHeader.header.cputype != CPU_TYPE_ARM64) {
        return ArchCompatibilityNotCompatible;
    }

    // Check if mremap_encrypted is available
    if (![MremapDumper isSupported]) {
        KJDebug(@"mremap_encrypted not available on this system");
        return ArchCompatibilityNotCompatible;
    }

    return ArchCompatibilityCompatible;
}

- (BOOL)dumpBinary {
    KJPrint(@"Dumping %@ (%@) using mremap_encrypted",
            self.originalBinary, [Dumper readableArchFromHeader:self.thinHeader]);

    // Get paths
    NSString *binaryPath = self.originalBinary.binaryPath;
    NSString *workingPath = self.originalBinary.workingPath;
    NSString *dumpPath = [workingPath stringByAppendingPathComponent:
                          binaryPath.lastPathComponent];

    // Create working directory if needed
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dumpPath.stringByDeletingLastPathComponent
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:&error];
    if (error) {
        KJPrint(@"Failed to create working directory: %@", error);
        return NO;
    }

    // First, allow invalid codesigned memory (required for mremap_encrypted)
    if (![MremapDecrypt allowInvalidCodesignedMemory]) {
        KJPrint(@"Failed to allow invalid codesigned memory");
        return NO;
    }

    // Perform decryption
    KJPrintVerbose(@"Decrypting %@ -> %@", binaryPath, dumpPath);

    if (![MremapDecrypt decryptBinary:binaryPath toOutput:dumpPath error:&error]) {
        KJPrint(@"Decryption failed: %@", error.localizedDescription);
        return NO;
    }

    KJPrint(@"Successfully dumped %@ with arch %@",
            self.originalBinary, [Dumper readableArchFromHeader:self.thinHeader]);

    return YES;
}

@end
