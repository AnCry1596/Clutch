//
//  MremapDumper.h
//  Clutch
//
//  Modern file-based dumper using mremap_encrypted syscall.
//  This replaces the legacy process-based dumping approach.
//

#import "Dumper.h"

NS_ASSUME_NONNULL_BEGIN

@interface MremapDumper : Dumper <BinaryDumpProtocol>

// Check if mremap_encrypted approach is available
+ (BOOL)isSupported;

@end

NS_ASSUME_NONNULL_END
