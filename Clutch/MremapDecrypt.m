//
//  MremapDecrypt.m
//  Clutch
//
//  Modern file-based decryption using mremap_encrypted syscall.
//  Based on UnFairPlay's simple and proven approach.
//

#import "MremapDecrypt.h"
#import "ClutchPrint.h"
#import <sys/mman.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <libkern/OSByteOrder.h>

// mremap_encrypted declaration - this is in libc but not publicly declared
extern int mremap_encrypted(void *addr, size_t len, uint32_t cryptid, uint32_t cputype, uint32_t cpusubtype);

@implementation MremapDecrypt

+ (BOOL)isAvailable {
    // mremap_encrypted is available on iOS 10+
    void *sym = dlsym(RTLD_DEFAULT, "mremap_encrypted");
    return sym != NULL;
}

+ (BOOL)allowInvalidCodesignedMemory {
    // On jailbroken devices with proper entitlements, mremap_encrypted
    // should work directly without needing CS_DEBUGGED flag.
    return YES;
}

#pragma mark - Simple File Copy (from UnFairPlay)

+ (BOOL)copyFile:(NSString *)src to:(NSString *)dest {
    if ([src isEqualToString:dest]) {
        return NO;
    }

    FILE *srcFp = fopen(src.UTF8String, "rb");
    FILE *destFp = fopen(dest.UTF8String, "wb");

    if (!srcFp || !destFp) {
        if (srcFp) fclose(srcFp);
        if (destFp) fclose(destFp);
        return NO;
    }

    // Get file size and copy in chunks
    fseek(srcFp, 0, SEEK_END);
    long fileSize = ftell(srcFp);
    fseek(srcFp, 0, SEEK_SET);

    const size_t bufSize = 1024 * 1024; // 1MB chunks
    void *buffer = malloc(bufSize);
    if (!buffer) {
        fclose(srcFp);
        fclose(destFp);
        return NO;
    }

    BOOL success = YES;
    size_t remaining = fileSize;
    while (remaining > 0) {
        size_t toRead = (remaining > bufSize) ? bufSize : remaining;
        size_t bytesRead = fread(buffer, 1, toRead, srcFp);
        if (bytesRead != toRead) {
            success = NO;
            break;
        }
        size_t bytesWritten = fwrite(buffer, 1, bytesRead, destFp);
        if (bytesWritten != bytesRead) {
            success = NO;
            break;
        }
        remaining -= bytesRead;
    }

    free(buffer);
    fclose(srcFp);
    fclose(destFp);

    return success;
}

#pragma mark - File Mapping (from UnFairPlay)

+ (uint8_t *)mapFile:(NSString *)path
            writable:(BOOL)writable
                size:(size_t *)outSize
          descriptor:(int *)outFd {

    int fd = open(path.UTF8String, writable ? O_RDWR : O_RDONLY);
    if (fd < 0) {
        KJPrint(@"Failed to open %@: %s", path, strerror(errno));
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        KJPrint(@"fstat failed: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    int prot = writable ? (PROT_READ | PROT_WRITE) : PROT_READ;
    int mapFlags = writable ? MAP_SHARED : MAP_PRIVATE;

    uint8_t *base = mmap(NULL, st.st_size, prot, mapFlags, fd, 0);
    if (base == MAP_FAILED) {
        KJPrint(@"mmap failed: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    *outSize = st.st_size;
    if (outFd) {
        *outFd = fd;
    } else {
        close(fd);
    }

    return base;
}

#pragma mark - Decryption Core (UnFairPlay style)

+ (int)unprotectSlice:(int)srcFd
            destData:(uint8_t *)destData
             encInfo:(struct encryption_info_command_64 *)encInfo
             cpuType:(cpu_type_t)cpuType
          cpuSubType:(cpu_subtype_t)cpuSubType {

    // Map the encrypted region directly from the source file
    // This is exactly how UnFairPlay does it
    void *cryptBase = mmap(NULL, encInfo->cryptsize, PROT_READ | PROT_EXEC,
                           MAP_PRIVATE, srcFd, encInfo->cryptoff);
    if (cryptBase == MAP_FAILED) {
        KJPrint(@"mmap for decryption failed: %s", strerror(errno));
        return 1;
    }

    // Decrypt the mapped region in place
    int result = mremap_encrypted(cryptBase, encInfo->cryptsize, encInfo->cryptid,
                                  cpuType, cpuSubType);
    if (result != 0) {
        KJPrint(@"mremap_encrypted failed: %s", strerror(errno));
        KJPrint(@"Try waiting 1 second and running again");
        munmap(cryptBase, encInfo->cryptsize);
        return 1;
    }

    // Copy decrypted data to destination
    memcpy(destData + encInfo->cryptoff, cryptBase, encInfo->cryptsize);

    munmap(cryptBase, encInfo->cryptsize);
    return 0;
}

+ (BOOL)decryptMachOSlice:(int)srcFd
                 srcData:(uint8_t *)srcData
                destData:(uint8_t *)destData
               machoOff:(size_t)machoOff {

    uint8_t *sliceSrc = srcData + machoOff;
    uint8_t *sliceDest = destData + machoOff;

    uint32_t magic = *(uint32_t *)sliceSrc;
    uint32_t ncmds = 0;
    uint32_t headerSize = 0;
    cpu_type_t cpuType = 0;
    cpu_subtype_t cpuSubType = 0;

    if (magic == MH_MAGIC_64) {
        struct mach_header_64 *header = (struct mach_header_64 *)sliceSrc;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        headerSize = sizeof(struct mach_header_64);
    } else if (magic == MH_MAGIC) {
        struct mach_header *header = (struct mach_header *)sliceSrc;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        headerSize = sizeof(struct mach_header);
    } else {
        KJPrint(@"Unknown Mach-O magic: 0x%x", magic);
        return NO;
    }

    // Find encryption info load command
    struct encryption_info_command_64 *encInfo = NULL;
    uint32_t encInfoOffset = 0;
    uint32_t offset = headerSize;

    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command *cmd = (struct load_command *)(sliceSrc + offset);

        if (cmd->cmd == LC_ENCRYPTION_INFO || cmd->cmd == LC_ENCRYPTION_INFO_64) {
            encInfo = (struct encryption_info_command_64 *)cmd;
            encInfoOffset = offset;
            break;
        }

        offset += cmd->cmdsize;
    }

    if (!encInfo || encInfo->cryptid == 0) {
        KJDebug(@"Binary is not encrypted or already decrypted");
        return YES; // Not an error, just nothing to do
    }

    KJPrintVerbose(@"Found encrypted segment: cryptoff=0x%x cryptsize=0x%x cryptid=%d",
                   encInfo->cryptoff, encInfo->cryptsize, encInfo->cryptid);

    // Create a temporary encryption_info_command with adjusted offset for FAT binaries
    struct encryption_info_command_64 adjustedInfo = *encInfo;
    adjustedInfo.cryptoff = (uint32_t)(machoOff + encInfo->cryptoff);

    // Decrypt the slice
    if ([self unprotectSlice:srcFd destData:destData encInfo:&adjustedInfo
                     cpuType:cpuType cpuSubType:cpuSubType] != 0) {
        return NO;
    }

    // Set cryptid to 0 in the destination to mark as decrypted
    struct encryption_info_command_64 *destEncInfo =
        (struct encryption_info_command_64 *)(sliceDest + encInfoOffset);
    destEncInfo->cryptid = 0;

    KJPrintVerbose(@"Successfully decrypted %u bytes", encInfo->cryptsize);
    return YES;
}

#pragma mark - Public Interface

+ (BOOL)decryptBinary:(NSString *)inputPath
             toOutput:(NSString *)outputPath
                error:(NSError **)error {

    // Ensure mremap_encrypted is available
    if (![self isAvailable]) {
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"mremap_encrypted not available"}];
        }
        return NO;
    }

    // Step 1: Copy the source file to destination (like UnFairPlay)
    KJDebug(@"Copying %@ to %@", inputPath, outputPath);
    if (![self copyFile:inputPath to:outputPath]) {
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to copy file"}];
        }
        return NO;
    }

    // Step 2: Map source file (read-only, keep fd open for mremap_encrypted)
    size_t srcSize = 0;
    int srcFd = -1;
    uint8_t *srcData = [self mapFile:inputPath writable:NO size:&srcSize descriptor:&srcFd];
    if (!srcData) {
        [[NSFileManager defaultManager] removeItemAtPath:outputPath error:nil];
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:3
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to map source file"}];
        }
        return NO;
    }

    // Step 3: Map destination file (read-write, for modification)
    size_t destSize = 0;
    uint8_t *destData = [self mapFile:outputPath writable:YES size:&destSize descriptor:NULL];
    if (!destData) {
        munmap(srcData, srcSize);
        close(srcFd);
        [[NSFileManager defaultManager] removeItemAtPath:outputPath error:nil];
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:4
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to map destination file"}];
        }
        return NO;
    }

    // Verify sizes match
    if (srcSize != destSize) {
        KJPrint(@"File size mismatch: src=%zu dest=%zu", srcSize, destSize);
        munmap(srcData, srcSize);
        munmap(destData, destSize);
        close(srcFd);
        [[NSFileManager defaultManager] removeItemAtPath:outputPath error:nil];
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:5
                                     userInfo:@{NSLocalizedDescriptionKey: @"File size mismatch after copy"}];
        }
        return NO;
    }

    BOOL success = YES;
    uint32_t magic = *(uint32_t *)srcData;

    // Handle FAT binary
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        BOOL isBigEndian = (magic == FAT_CIGAM);
        struct fat_header *fatHeader = (struct fat_header *)srcData;
        struct fat_arch *fatArches = (struct fat_arch *)(fatHeader + 1);

        uint32_t nArches = isBigEndian ? OSSwapInt32(fatHeader->nfat_arch) : fatHeader->nfat_arch;
        KJPrintVerbose(@"FAT binary with %u architectures", nArches);

        for (uint32_t i = 0; i < nArches; i++) {
            uint32_t archOffset = isBigEndian ? OSSwapInt32(fatArches[i].offset) : fatArches[i].offset;

            KJDebug(@"Processing FAT slice %u at offset 0x%x", i, archOffset);

            if (![self decryptMachOSlice:srcFd
                                srcData:srcData
                               destData:destData
                               machoOff:archOffset]) {
                KJPrint(@"Failed to decrypt FAT slice %u", i);
                // Continue with other slices - don't fail completely
            }
        }
    } else {
        // Single architecture - follow UnFairPlay exactly
        KJDebug(@"Single architecture binary");
        success = [self decryptMachOSlice:srcFd
                                 srcData:srcData
                                destData:destData
                                machoOff:0];
    }

    // Ensure changes are written to disk
    msync(destData, destSize, MS_SYNC);

    // Cleanup
    munmap(srcData, srcSize);
    munmap(destData, destSize);
    close(srcFd);

    if (!success) {
        [[NSFileManager defaultManager] removeItemAtPath:outputPath error:nil];
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:6
                                     userInfo:@{NSLocalizedDescriptionKey: @"Decryption failed"}];
        }
    }

    return success;
}

@end
