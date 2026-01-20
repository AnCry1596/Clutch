//
//  MremapDecrypt.m
//  Clutch
//
//  Modern file-based decryption using mremap_encrypted syscall.
//

#import "MremapDecrypt.h"
#import "ClutchPrint.h"
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/syscall.h>
#import <fcntl.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <libkern/OSByteOrder.h>

// ptrace constants for self-debugging
#define PT_TRACE_ME     0
#define PT_ATTACHEXC    14

// Code signing status
#define CS_OPS_STATUS       0
#define CS_DEBUGGED         0x10000000

// External declarations
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

// mremap_encrypted declaration - this is in libc but not publicly declared
extern int mremap_encrypted(void *addr, size_t len, uint32_t cryptid, uint32_t cputype, uint32_t cpusubtype);

@implementation MremapDecrypt

static BOOL _allowsInvalidCodesignedMemory = NO;

+ (BOOL)isAvailable {
    // mremap_encrypted is available on iOS 10+
    // Check by attempting to resolve the symbol
    void *sym = dlsym(RTLD_DEFAULT, "mremap_encrypted");
    return sym != NULL;
}

+ (BOOL)allowInvalidCodesignedMemory {
    if (_allowsInvalidCodesignedMemory) {
        return YES;
    }

    // Check if already debugged
    uint32_t flags = 0;
    csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    if (flags & CS_DEBUGGED) {
        _allowsInvalidCodesignedMemory = YES;
        return YES;
    }

    // Self-debug using fork + ptrace trick
    // This marks the process as CS_DEBUGGED, allowing invalid codesigned pages
    pid_t pid = fork();

    if (pid == 0) {
        // Child process - trace itself and exit
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wdeprecated-declarations"
        syscall(SYS_ptrace, PT_TRACE_ME, 0, 0, 0);
        #pragma clang diagnostic pop
        _exit(0);
    } else if (pid < 0) {
        KJPrint(@"fork() failed: %s", strerror(errno));
        return NO;
    }

    // Wait for child to exit
    int status;
    waitpid(pid, &status, 0);

    _allowsInvalidCodesignedMemory = YES;
    return YES;
}

#pragma mark - File Mapping

+ (uint8_t *)mapFile:(NSString *)path
            writable:(BOOL)writable
                size:(size_t *)outSize
          descriptor:(int *)outFd {

    int flags = writable ? (O_CREAT | O_TRUNC | O_RDWR) : O_RDONLY;
    int fd = open(path.UTF8String, flags, 0755);

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

    if (writable && *outSize > 0) {
        if (ftruncate(fd, *outSize) < 0) {
            KJPrint(@"ftruncate failed: %s", strerror(errno));
            close(fd);
            return NULL;
        }
        st.st_size = *outSize;
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

#pragma mark - Decryption Core

+ (BOOL)decryptMachOSlice:(int)fd
                inputData:(uint8_t *)inputData
               outputData:(uint8_t *)outputData
                machoOff:(size_t)machoOff {

    uint32_t magic = *(uint32_t *)inputData;
    uint32_t ncmds = 0;
    uint32_t headerSize = 0;
    cpu_type_t cpuType = 0;
    cpu_subtype_t cpuSubType = 0;

    if (magic == MH_MAGIC_64) {
        struct mach_header_64 *header = (struct mach_header_64 *)inputData;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        headerSize = sizeof(struct mach_header_64);
    } else if (magic == MH_MAGIC) {
        struct mach_header *header = (struct mach_header *)inputData;
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
        struct load_command *cmd = (struct load_command *)(inputData + offset);

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

    // Allocate buffer for decrypted data
    void *decryptedBuf = malloc(encInfo->cryptsize);
    if (!decryptedBuf) {
        KJPrint(@"Failed to allocate decryption buffer");
        return NO;
    }

    BOOL success = NO;

    // Check if cryptoff is page-aligned (16KB on iOS)
    size_t pageSize = 0x4000; // 16KB

    if ((encInfo->cryptoff & (pageSize - 1)) == 0) {
        // Page-aligned - simple case
        KJDebug(@"Encryption offset is 16k aligned, using direct mremap_encrypted");

        void *cryptBase = mmap(NULL, encInfo->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, encInfo->cryptoff + machoOff);
        if (cryptBase == MAP_FAILED) {
            KJPrint(@"mmap for decryption failed: %s", strerror(errno));
            free(decryptedBuf);
            return NO;
        }

        int result = mremap_encrypted(cryptBase, encInfo->cryptsize, encInfo->cryptid, cpuType, cpuSubType);
        if (result != 0) {
            KJPrint(@"mremap_encrypted failed: %s", strerror(errno));
            munmap(cryptBase, encInfo->cryptsize);
            free(decryptedBuf);
            return NO;
        }

        memcpy(decryptedBuf, cryptBase, encInfo->cryptsize);
        munmap(cryptBase, encInfo->cryptsize);
        success = YES;

    } else {
        // Not page-aligned - need to handle page by page
        KJDebug(@"Encryption offset is NOT 16k aligned, using page-by-page decryption");

        size_t offAligned = encInfo->cryptoff & ~(pageSize - 1);

        for (size_t off = offAligned; off < encInfo->cryptoff + encInfo->cryptsize; off += pageSize) {
            size_t offEnd = MIN(off + pageSize, encInfo->cryptoff + encInfo->cryptsize);
            size_t curMapLen = offEnd - off;
            if ((curMapLen & (pageSize - 1)) == 0) {
                curMapLen = pageSize;
            } else {
                curMapLen = (curMapLen + pageSize - 1) & ~(pageSize - 1);
            }

            size_t inPageStart = (off < encInfo->cryptoff) ? (encInfo->cryptoff - off) : 0;
            size_t cryptOff = off + inPageStart;

            void *cryptBase = mmap(NULL, curMapLen, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, off + machoOff);
            if (cryptBase == MAP_FAILED) {
                KJPrint(@"mmap for page decryption failed: %s", strerror(errno));
                free(decryptedBuf);
                return NO;
            }

            int result = mremap_encrypted(cryptBase, curMapLen, encInfo->cryptid, cpuType, cpuSubType);
            if (result != 0) {
                KJPrint(@"mremap_encrypted for page failed: %s", strerror(errno));
                munmap(cryptBase, curMapLen);
                free(decryptedBuf);
                return NO;
            }

            size_t copyLen = MIN(curMapLen - inPageStart, encInfo->cryptoff + encInfo->cryptsize - cryptOff);
            memcpy((char *)decryptedBuf + (cryptOff - encInfo->cryptoff), (char *)cryptBase + inPageStart, copyLen);

            munmap(cryptBase, curMapLen);
        }
        success = YES;
    }

    if (success) {
        // Copy decrypted data to output
        memcpy(outputData + encInfo->cryptoff, decryptedBuf, encInfo->cryptsize);

        // Clear cryptid to mark as decrypted
        struct encryption_info_command_64 *outEncInfo = (struct encryption_info_command_64 *)(outputData + encInfoOffset);
        outEncInfo->cryptid = 0;

        KJPrintVerbose(@"Successfully decrypted %u bytes", encInfo->cryptsize);
    }

    free(decryptedBuf);
    return success;
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

    // Allow invalid codesigned memory
    if (![self allowInvalidCodesignedMemory]) {
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to allow invalid codesigned memory"}];
        }
        return NO;
    }

    // Map input file
    size_t inputSize = 0;
    int inputFd = -1;
    uint8_t *inputData = [self mapFile:inputPath writable:NO size:&inputSize descriptor:&inputFd];
    if (!inputData) {
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:3
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to map input file"}];
        }
        return NO;
    }

    // Map output file (same size as input)
    size_t outputSize = inputSize;
    uint8_t *outputData = [self mapFile:outputPath writable:YES size:&outputSize descriptor:NULL];
    if (!outputData) {
        munmap(inputData, inputSize);
        close(inputFd);
        if (error) {
            *error = [NSError errorWithDomain:@"MremapDecrypt"
                                         code:4
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to map output file"}];
        }
        return NO;
    }

    // Copy original data to output
    memcpy(outputData, inputData, inputSize);

    BOOL success = YES;
    uint32_t magic = *(uint32_t *)inputData;

    // Handle FAT binary
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        BOOL isBigEndian = (magic == FAT_CIGAM);
        struct fat_header *fatHeader = (struct fat_header *)inputData;
        struct fat_arch *fatArches = (struct fat_arch *)(fatHeader + 1);

        uint32_t nArches = isBigEndian ? OSSwapInt32(fatHeader->nfat_arch) : fatHeader->nfat_arch;
        KJPrintVerbose(@"FAT binary with %u architectures", nArches);

        for (uint32_t i = 0; i < nArches; i++) {
            uint32_t archOffset = isBigEndian ? OSSwapInt32(fatArches[i].offset) : fatArches[i].offset;

            KJDebug(@"Processing FAT slice %u at offset 0x%x", i, archOffset);

            if (![self decryptMachOSlice:inputFd
                               inputData:inputData + archOffset
                              outputData:outputData + archOffset
                               machoOff:archOffset]) {
                KJPrint(@"Failed to decrypt FAT slice %u", i);
                // Continue with other slices
            }
        }
    } else {
        // Single architecture
        KJDebug(@"Single architecture binary");
        success = [self decryptMachOSlice:inputFd
                                inputData:inputData
                               outputData:outputData
                                machoOff:0];
    }

    // Cleanup
    munmap(inputData, inputSize);
    munmap(outputData, outputSize);
    close(inputFd);

    if (!success && error) {
        *error = [NSError errorWithDomain:@"MremapDecrypt"
                                     code:5
                                 userInfo:@{NSLocalizedDescriptionKey: @"Decryption failed"}];
    }

    return success;
}

@end
