// Build: gcc -O2 -std=c17 -Wall -Wextra mkfs_builder_skeleton.c -o mkfs_builder  // Build command hint
#define _FILE_OFFSET_BITS 64 // Use 64-bit file offsets (off_t)
#include <stdio.h>            // Standard I/O
#include <stdlib.h>           // Memory allocation, exit codes
#include <stdint.h>           // Fixed width integer types
#include <string.h>           // memset, memcpy, strcmp
#include <inttypes.h>         // PRIu64 macros for printing uint64_t
#include <errno.h>            // errno error reporting
#include <time.h>             // time() for timestamps
#include <assert.h>           // assert (not heavily used here)
#include <ctype.h>            // ctype helpers (not used but included)

#define BS 4096u               // Filesystem block size (4KiB)
#define INODE_SIZE 128u        // On-disk inode size in bytes
#define ROOT_INO 1u            // Root inode number (fixed to 1)

uint64_t g_random_seed = 0; // Placeholder for future randomness (unused now)

// Basic on-disk data structures (packed)
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;              // Magic number identifying MiniVSFS (0x4D565346)
    uint32_t version;            // Filesystem version (1)
    uint32_t block_size;         // Block size in bytes (4096)
    uint64_t total_blocks;       // Total number of blocks in the image
    uint64_t inode_count;        // Total number of inodes provisioned
    uint64_t inode_bitmap_start; // Block index of inode bitmap
    uint64_t inode_bitmap_blocks;// Length (blocks) of inode bitmap (==1)
    uint64_t data_bitmap_start;  // Block index of data bitmap
    uint64_t data_bitmap_blocks; // Length (blocks) of data bitmap (==1)
    uint64_t inode_table_start;  // First block of inode table
    uint64_t inode_table_blocks; // Number of blocks in inode table
    uint64_t data_region_start;  // First block index of data region
    uint64_t data_region_blocks; // Number of data blocks available
    uint64_t root_inode;         // Root inode number (1)
    uint64_t mtime_epoch;        // Last modification time (epoch seconds)
    uint32_t flags;              // Feature / status flags (unused)
    uint32_t checksum;           // CRC32 of first 4092 bytes of superblock
} superblock_t;
#pragma pack(pop)
_Static_assert(sizeof(superblock_t) == 116, "superblock must fit in one block"); // Validate size

#pragma pack(push,1)
typedef struct {
    uint16_t mode;        // File type + permissions (octal style like UNIX)
    uint16_t links;       // Hard link count
    uint32_t uid;         // Owner user id
    uint32_t gid;         // Owner group id
    uint64_t size_bytes;  // Logical file size in bytes
    uint64_t atime;       // Last access time
    uint64_t mtime;       // Last modification time
    uint64_t ctime;       // Creation / status change time
    uint32_t direct[12];  // Direct data block pointers (absolute block numbers)
    uint32_t reserved_0;  // Padding / future use
    uint32_t reserved_1;  // Padding / future use
    uint32_t reserved_2;  // Padding / future use
    uint32_t proj_id;     // Project ID (arbitrary demo field)
    uint32_t uid16_gid16; // Packed legacy uid/gid (unused)
    uint64_t xattr_ptr;   // Extended attributes pointer (unused)
    uint64_t inode_crc;   // Low 32 bits: CRC32 of bytes [0..119]; high 32 bits zero
} inode_t;
#pragma pack(pop)
_Static_assert(sizeof(inode_t)==INODE_SIZE, "inode size mismatch"); // Ensure 128 bytes

#pragma pack(push,1)
typedef struct {
    uint32_t inode_no;  // Target inode number (0 means slot free)
    uint8_t  type;      // Entry type: 2=dir,1=file
    char     name[58];  // Null-padded name (not guaranteed null terminated)
    uint8_t  checksum;  // XOR checksum of first 63 bytes
} dirent64_t;
#pragma pack(pop)
_Static_assert(sizeof(dirent64_t)==64, "dirent size mismatch"); // Each dir entry exactly 64 bytes

// ==========================DO NOT CHANGE THIS PORTION=========================
// CRC32 helper implementation for metadata integrity
uint32_t CRC32_TAB[256]; // Precomputed polynomial table
void crc32_init(void){ // Initialize CRC lookup table
    for (uint32_t i=0;i<256;i++){ // For each possible byte value
        uint32_t c=i;              // Start with current index
        for(int j=0;j<8;j++)       // Process 8 bits
            c = (c&1)?(0xEDB88320u^(c>>1)):(c>>1); // Polynomial reduction
        CRC32_TAB[i]=c;            // Store table value
    }
}
uint32_t crc32(const void* data, size_t n){ // Compute CRC32 over buffer
    const uint8_t* p=(const uint8_t*)data; // Byte pointer
    uint32_t c=0xFFFFFFFFu;               // Initial XOR value
    for(size_t i=0;i<n;i++)               // Iterate all bytes
        c = CRC32_TAB[(c^p[i])&0xFF] ^ (c>>8); // Table-driven step
    return c ^ 0xFFFFFFFFu;               // Final XOR
}
// ==================== CRC32 END ====================

static uint32_t superblock_crc_finalize(superblock_t *sb) { // Finalize and store superblock CRC
    sb->checksum = 0;                        // Zero checksum field before computing
    uint32_t s = crc32((void *) sb, BS - 4); // Compute CRC over first 4092 bytes
    sb->checksum = s;                        // Store computed CRC
    return s;                                // Return value (optional use)
}

void inode_crc_finalize(inode_t* ino){ // Compute and store inode CRC
    uint8_t tmp[INODE_SIZE];           // Temporary copy buffer
    memcpy(tmp, ino, INODE_SIZE);      // Copy inode bytes
    memset(&tmp[120], 0, 8);           // Zero CRC storage area before hashing
    uint32_t c = crc32(tmp, 120);      // Compute CRC over first 120 bytes
    ino->inode_crc = (uint64_t)c;      // Store CRC (lower 32 bits)
}

void dirent_checksum_finalize(dirent64_t* de) { // Compute dirent XOR checksum
    const uint8_t* p = (const uint8_t*)de;   // Byte pointer
    uint8_t x = 0;                           // Accumulator
    for (int i = 0; i < 63; i++)             // Iterate first 63 bytes
        x ^= p[i];                           // XOR accumulate
    de->checksum = x;                        // Store checksum
}

static void usage(const char* prog){ // Print CLI usage string
    fprintf(stderr, "Usage: %s --image <out.img> --size-kib <180..4096 multiple of 4> --inodes <128..512> [--seed <n>]\n", prog);
}

static int parse_u64(const char* s, uint64_t* out){ // Parse unsigned 64-bit integer from string
    if(!s || !*s) {                // Reject null/empty
        return -1;                 // Indicate parse failure
    }
    char* end = NULL;              // End pointer for strtoull
    errno = 0;                     // Clear errno
    unsigned long long v = strtoull(s, &end, 10); // Parse base-10 number
    if(errno || *end != '\0') {    // Check errors or trailing chars
        return -1;                 // Invalid input
    }
    *out = (uint64_t)v;            // Store result
    return 0;                      // Success
}

static void set_bit(uint8_t* bm, uint64_t idx){ // Set bit in bitmap
    bm[idx/8] |= (uint8_t)(1u << (idx%8));      // Set corresponding bit
}

int main(int argc, char** argv) {  // Program entry
    crc32_init();                  // Initialize CRC table

    const char* image_path = NULL; // Output image path
    uint64_t size_kib = 0;         // Requested size in KiB
    uint64_t inode_count = 0;      // Requested inode count
    uint64_t seed = 0;             // Optional seed value
    int have_seed = 0;             // Flag if seed provided

    for(int i = 1; i < argc; i++) {                 // Iterate arguments
        if(strcmp(argv[i], "--image") == 0 && i + 1 < argc) {          // --image option
            image_path = argv[++i];                                     // Capture path
        } else if(strcmp(argv[i], "--size-kib") == 0 && i + 1 < argc) { // --size-kib option
            if(parse_u64(argv[++i], &size_kib)) {                       // Parse size
                fprintf(stderr, "Invalid --size-kib\n");              // Error message
                return 2;                                              // Exit code
            }
        } else if(strcmp(argv[i], "--inodes") == 0 && i + 1 < argc) {  // --inodes option
            if(parse_u64(argv[++i], &inode_count)) {                    // Parse count
                fprintf(stderr, "Invalid --inodes\n");               // Error
                return 2;                                              // Exit
            }
        } else if(strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {    // --seed option
            if(parse_u64(argv[++i], &seed)) {                           // Parse seed
                fprintf(stderr, "Invalid --seed\n");                 // Error
                return 2;                                              // Exit
            }
            have_seed = 1;                                             // Mark seed present
        } else if(strcmp(argv[i], "--help") == 0) {                    // Help option
            usage(argv[0]);                                            // Show usage
            return 0;                                                  // Normal exit
        } else {                                                        // Unknown option
            fprintf(stderr, "Unknown or incomplete argument: %s\n", argv[i]); // Report
            usage(argv[0]);                                            // Show usage
            return 2;                                                  // Error exit
        }
    }

    if(!image_path || !size_kib || !inode_count) { // Validate required args
        usage(argv[0]);                             // Show usage
        return 2;                                   // Error exit
    }

    if(size_kib < 180 || size_kib > 4096 || (size_kib % 4) != 0) { // Validate size range
        fprintf(stderr, "size-kib out of range or not multiple of 4\n"); // Report error
        return 2;                                                  // Exit
    }

    if(inode_count < 128 || inode_count > 512) { // Validate inode range
        fprintf(stderr, "inodes out of range\n"); // Report error
        return 2;                                // Exit
    }
    g_random_seed = have_seed ? seed : (uint64_t)time(NULL); // Initialize RNG seed fallback

    uint64_t total_blocks = (size_kib * 1024ull) / BS; // Compute total blocks of image
    uint64_t inode_table_bytes = inode_count * INODE_SIZE; // Total bytes for inode table
    uint64_t inode_table_blocks = (inode_table_bytes + BS - 1) / BS; // Round up to block count
    if(inode_table_blocks == 0) {      // Safety: ensure at least one block
        inode_table_blocks = 1;        // Force minimum
    }
    uint64_t used_meta = 1 + 1 + 1 + inode_table_blocks; // Blocks: super + inode bm + data bm + inode table
    if(used_meta >= total_blocks) {    // Ensure room for data region
        fprintf(stderr, "Insufficient blocks for metadata layout\n"); // Error
        return 3;                       // Exit
    }
    uint64_t data_region_blocks = total_blocks - used_meta; // Compute data block count
    if(data_region_blocks == 0) {      // No space left for data
        fprintf(stderr, "No data blocks available\n"); // Error
        return 3;                       // Exit
    }

    superblock_t sb;                   // Superblock instance
    memset(&sb, 0, sizeof(sb));        // Zero initialize
    sb.magic = 0x4D565346u;            // Set magic signature
    sb.version = 1;                    // Version 1
    sb.block_size = BS;                // Store block size
    sb.total_blocks = total_blocks;    // Total blocks
    sb.inode_count = inode_count;      // Number of inodes
    sb.inode_bitmap_start = 1;         // Inode bitmap block index
    sb.inode_bitmap_blocks = 1;        // One block for bitmap
    sb.data_bitmap_start = 2;          // Data bitmap block index
    sb.data_bitmap_blocks = 1;         // One block for bitmap
    sb.inode_table_start = 3;          // Inode table starts at block 3
    sb.inode_table_blocks = inode_table_blocks; // Length of inode table
    sb.data_region_start = sb.inode_table_start + sb.inode_table_blocks; // Data region start block
    sb.data_region_blocks = data_region_blocks; // Data block count
    sb.root_inode = ROOT_INO;          // Root inode number
    sb.mtime_epoch = (uint64_t)time(NULL); // Current timestamp
    sb.flags = 0;                      // No flags
    superblock_crc_finalize(&sb);      // Compute and store superblock CRC

    uint8_t* inode_bitmap = calloc(1, BS); // Allocate and zero inode bitmap
    uint8_t* data_bitmap  = calloc(1, BS); // Allocate and zero data bitmap
    if(!inode_bitmap || !data_bitmap) { // Check allocations
        fprintf(stderr, "OOM\n");     // Out of memory
        return 5;                     // Exit
    }

    set_bit(inode_bitmap, 0);          // Mark root inode allocated
    set_bit(data_bitmap, 0);           // Mark first data block (root dir) allocated

    uint64_t it_bytes = inode_table_blocks * BS; // Total inode table bytes (rounded)
    uint8_t* inode_table = calloc(1, it_bytes);  // Allocate full inode table
    if(!inode_table) {                 // Check allocation
        fprintf(stderr, "OOM inode table\n"); // Error
        return 5;                      // Exit
    }

    inode_t root;                      // Root inode structure
    memset(&root, 0, sizeof(root));    // Zero initialize
    root.mode = 0040000;               // Directory type (simple)
    root.links = 2;                    // '.' and '..' entries
    root.uid = 0;                      // Owner UID
    root.gid = 0;                      // Owner GID
    root.proj_id = 4;                  // Arbitrary project id
    root.uid16_gid16 = 0;              // Legacy packed fields unused
    root.xattr_ptr = 0;                // No xattrs
    root.size_bytes = 128;             // Two dir entries (2 * 64)
    root.atime = sb.mtime_epoch;       // Access time
    root.mtime = sb.mtime_epoch;       // Modification time
    root.ctime = sb.mtime_epoch;       // Change time
    root.direct[0] = (uint32_t)sb.data_region_start; // First data block for directory
    for(int i = 1; i < 12; i++) {      // Clear remaining direct pointers
        root.direct[i] = 0;            // Zero unused slots
    }
    inode_crc_finalize(&root);         // Compute root inode CRC
    memcpy(inode_table, &root, sizeof(root)); // Store root inode into table slot 0

    uint64_t data_bytes = data_region_blocks * BS; // Total bytes in data region
    uint8_t* data_region = calloc(1, data_bytes);  // Allocate zeroed data region
    if(!data_region) {                 // Check allocation
        fprintf(stderr, "OOM data region\n"); // Error
        return 5;                      // Exit
    }

    dirent64_t de;                     // Directory entry builder
    memset(&de, 0, sizeof(de));        // Zero entry
    de.inode_no = ROOT_INO;            // '.' points to root
    de.type = 2;                       // Directory type
    memset(de.name, 0, sizeof(de.name)); // Clear name field
    de.name[0] = '.';                  // Name '.'
    dirent_checksum_finalize(&de);     // Compute checksum
    memcpy(data_region, &de, sizeof(de)); // Write '.' entry at offset 0

    memset(&de, 0, sizeof(de));        // Reset entry struct
    de.inode_no = ROOT_INO;            // '..' also points to root (self parent)
    de.type = 2;                       // Directory type
    memset(de.name, 0, sizeof(de.name)); // Clear name
    de.name[0] = '.';                  // First char '.'
    de.name[1] = '.';                  // Second char '.' forming '..'
    dirent_checksum_finalize(&de);     // Compute checksum
    memcpy(data_region + 64, &de, sizeof(de)); // Write '..' entry at second slot

    FILE* f = fopen(image_path, "wb+"); // Open image file for writing
    if(!f) {                            // Check open
        fprintf(stderr, "Cannot open output image %s: %s\n", image_path, strerror(errno)); // Error
        return 6;                       // Exit
    }
    if(fseek(f, (long)(total_blocks * BS) - 1, SEEK_SET) != 0) { // Pre-size file to full length
        fprintf(stderr, "fseek size prep failed\n"); // Error
        return 7;                       // Exit
    }
    if(fwrite("\0", 1, 1, f) != 1) {   // Write single zero byte at end to allocate space
        fprintf(stderr, "size extend write failed\n"); // Error
        return 7;                       // Exit
    }

    #define WRITE_AT_BLOCK(block_index, buf, len_desc, expected_bytes) do {            /* Helper macro to position and write a full block */ \
        if(fseek(f, (long)(block_index) * BS, SEEK_SET) != 0) {                        /* Seek to block offset */ \
            fprintf(stderr, "fseek failed for %s (block %llu)\n", len_desc, (unsigned long long)(block_index)); /* Error */ \
            return 7;                                                                   /* Exit on failure */ \
        }                                                                               \
        if(fwrite(buf, 1, expected_bytes, f) != (size_t)expected_bytes) {              /* Write block bytes */ \
            fprintf(stderr, "fwrite failed for %s\n", len_desc);                      /* Error */ \
            return 7;                                                                   /* Exit */ \
        }                                                                               \
    } while(0)

    uint8_t sb_block[BS];                  // Temporary block buffer for superblock area
    memset(sb_block, 0, sizeof(sb_block)); // Zero entire block
    memcpy(sb_block, &sb, sizeof(sb));     // Copy superblock structure into start
    WRITE_AT_BLOCK(0, sb_block, "superblock", BS); // Write block 0
    WRITE_AT_BLOCK(sb.inode_bitmap_start, inode_bitmap, "inode bitmap", BS); // Write inode bitmap
    WRITE_AT_BLOCK(sb.data_bitmap_start, data_bitmap, "data bitmap", BS);    // Write data bitmap
    for(uint64_t b = 0; b < inode_table_blocks; b++) { // Iterate inode table blocks
        WRITE_AT_BLOCK(sb.inode_table_start + b, inode_table + b * BS, "inode table block", BS); // Write each
    }
    for(uint64_t b = 0; b < data_region_blocks; b++) { // Iterate data blocks
        WRITE_AT_BLOCK(sb.data_region_start + b, data_region + b * BS, "data region block", BS); // Write each
    }
    #undef WRITE_AT_BLOCK              // Undefine helper macro
    fflush(f);                         // Flush OS buffers
    fclose(f);                         // Close image file

    free(inode_bitmap);                // Free inode bitmap memory
    free(data_bitmap);                 // Free data bitmap memory
    free(inode_table);                 // Free inode table buffer
    free(data_region);                 // Free data region buffer
    fprintf(stdout, "Created MiniVSFS image %s: blocks=%" PRIu64 ", inodes=%" PRIu64 ", data_blocks=%" PRIu64 "\n", image_path, total_blocks, inode_count, data_region_blocks);               // Summary output
    return 0;                          // Successful exit
}
