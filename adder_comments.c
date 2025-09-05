#define _FILE_OFFSET_BITS 64 // Enable large file support (64-bit off_t)
#include <stdio.h>            // Standard I/O functions
#include <stdint.h>           // Fixed-width integer types
#include <stdlib.h>           // malloc, free, exit codes
#include <string.h>           // memset, memcpy, strcmp, strerror
#include <errno.h>            // errno for error reporting
#include <time.h>             // time() for timestamps
#include <inttypes.h>         // PRIu64 format macros
#include <sys/stat.h>         // stat() for file metadata
#include <unistd.h>           // POSIX API (not heavily used here)

#define BS 4096u              // Filesystem block size in bytes
#define INODE_SIZE 128u       // On-disk inode size
#define ROOT_INO 1u           // Root inode number (fixed constant)
#define DIRECT_MAX 12         // Max direct pointers per inode
#pragma pack(push, 1)         // Pack structures to exact byte layout

typedef struct {
    uint32_t magic;              // Magic signature 0x4D565346 ('MVFS')
    uint32_t version;            // Filesystem version (1)
    uint32_t block_size;         // Block size must be 4096
    uint64_t total_blocks;       // Total number of blocks in image
    uint64_t inode_count;        // Provisioned inode count
    uint64_t inode_bitmap_start; // Block index of inode bitmap
    uint64_t inode_bitmap_blocks;// Number of blocks for inode bitmap
    uint64_t data_bitmap_start;  // Block index of data bitmap
    uint64_t data_bitmap_blocks; // Number of blocks for data bitmap
    uint64_t inode_table_start;  // First block of inode table
    uint64_t inode_table_blocks; // Number of blocks in inode table
    uint64_t data_region_start;  // First block of data region
    uint64_t data_region_blocks; // Number of blocks in data region
    uint64_t root_inode;         // Root inode number (should be 1)
    uint64_t mtime_epoch;        // Last modification timestamp (epoch seconds)
    uint32_t flags;              // Reserved flags (unused)
    uint32_t checksum;           // CRC32 of first 4092 bytes of this block
} superblock_t;                  // Superblock definition
#pragma pack(pop)                // Restore packing
_Static_assert(sizeof(superblock_t) == 116, "superblock must fit in one block"); // Ensure size

#pragma pack(push,1)            // Pack inode structure
typedef struct {
    uint16_t mode;        // File mode/type (e.g. dir/file)
    uint16_t links;       // Hard link count
    uint32_t uid;         // Owner user id
    uint32_t gid;         // Owner group id
    uint64_t size_bytes;  // Logical file size
    uint64_t atime;       // Last access time
    uint64_t mtime;       // Last modification time
    uint64_t ctime;       // Creation / status change time
    uint32_t direct[12];  // Direct data block pointers
    uint32_t reserved_0;  // Reserved / padding
    uint32_t reserved_1;  // Reserved / padding
    uint32_t reserved_2;  // Reserved / padding
    uint32_t proj_id;     // Project id (arbitrary)
    uint32_t uid16_gid16; // Packed legacy ids (unused)
    uint64_t xattr_ptr;   // Extended attribute pointer (unused)
    uint64_t inode_crc;   // Lower 32 bits: CRC32 over bytes [0..119]
} inode_t;                // Inode definition
#pragma pack(pop)         // Restore alignment
_Static_assert(sizeof(inode_t)==INODE_SIZE, "inode size mismatch"); // Validate size

#pragma pack(push,1)    // Pack dirent
typedef struct {
    uint32_t inode_no;  // Referenced inode number (0 => free slot)
    uint8_t  type;      // 2=directory, 1=file
    char     name[58];  // Name (not necessarily null-terminated)
    uint8_t  checksum;  // XOR checksum of first 63 bytes
} dirent64_t;           // Directory entry structure
#pragma pack(pop)       // Restore packing
_Static_assert(sizeof(dirent64_t)==64, "dirent size mismatch"); // Validate entry size

// ==========================DO NOT CHANGE THIS PORTION=========================
// CRC32 implementation for integrity fields
uint32_t CRC32_TAB[256];        // Lookup table storage
void crc32_init(void){          // Initialize CRC table
    for (uint32_t i=0;i<256;i++){       // For each possible byte
        uint32_t c=i;                   // Start value
        for(int j=0;j<8;j++)            // Process 8 bits
            c = (c&1)?(0xEDB88320u^(c>>1)):(c>>1); // Polynomial step
        CRC32_TAB[i]=c;                 // Store entry
    }
}
uint32_t crc32(const void* data, size_t n){ // Compute CRC32 over buffer
    const uint8_t* p=(const uint8_t*)data;  // Byte pointer
    uint32_t c=0xFFFFFFFFu;                 // Initial value
    for(size_t i=0;i<n;i++)                // Loop through bytes
        c = CRC32_TAB[(c^p[i])&0xFF] ^ (c>>8); // Update state
    return c ^ 0xFFFFFFFFu;                 // Finalize
}
// ====================================CRC32====================================

static uint32_t superblock_crc_finalize(superblock_t *sb) { // Compute & store superblock CRC
    sb->checksum = 0;                                      // Clear existing checksum
    uint32_t s = crc32((void *) sb, BS - 4);               // CRC over first 4092 bytes
    sb->checksum = s;                                      // Save result
    return s;                                              // Return checksum
}

void inode_crc_finalize(inode_t* ino){ // Compute inode CRC
    uint8_t tmp[INODE_SIZE];            // Temp buffer
    memcpy(tmp, ino, INODE_SIZE);       // Copy inode
    memset(&tmp[120], 0, 8);            // Zero CRC field
    uint32_t c = crc32(tmp, 120);       // Compute CRC
    ino->inode_crc = (uint64_t)c;       // Store as 64-bit (low 32 bits used)
}

void dirent_checksum_finalize(dirent64_t* de) { // Compute dirent checksum
    const uint8_t* p = (const uint8_t*)de;     // Byte pointer
    uint8_t x = 0;                             // Accumulator
    for (int i = 0; i < 63; i++)               // Iterate first 63 bytes
        x ^= p[i];                             // XOR accumulate
    de->checksum = x;                          // Store checksum
}

static void usage(const char* prog){ // Print usage help
    fprintf(stderr, "Usage: %s --input <in.img> --output <out.img> --file <path>\n", prog);
}

static void set_bit(uint8_t* bm, uint64_t idx){  // Set bit in bitmap array
    bm[idx/8] |= (uint8_t)(1u<<(idx%8));         // Compute byte & bit positions
}

static int find_first_zero_bit(uint8_t* bm, uint64_t max_bits){ // Scan free bit
    for(uint64_t i=0;i<max_bits;i++){          // Iterate bits
        if( (bm[i/8] & (1u<<(i%8))) == 0){     // If bit is clear
            return (int)i;                     // Return index
        }
    }
    return -1;                                 // None free
}

int main(int argc, char** argv) {  // Entry point
    crc32_init();                  // Initialize CRC tables
    const char *input=NULL,*output=NULL,*filepath=NULL; // CLI argument holders
    for(int i=1;i<argc;i++){       // Parse arguments loop
        if(strcmp(argv[i],"--input")==0 && i+1<argc) input=argv[++i];           // Capture input image
        else if(strcmp(argv[i],"--output")==0 && i+1<argc) output=argv[++i];    // Capture output image
        else if(strcmp(argv[i],"--file")==0 && i+1<argc) filepath=argv[++i];    // Capture file to add
        else if(strcmp(argv[i],"--help")==0){ usage(argv[0]); return 0; }       // Help request
        else { fprintf(stderr,"Unknown/incomplete argument %s\n", argv[i]); usage(argv[0]); return 2; } // Error
    }
    if(!input || !output || !filepath) { usage(argv[0]); return 2; } // Require mandatory args

    { // Scoped block: copy source image to destination
        FILE* src = fopen(input, "rb");             // Open input image for reading
        if(!src) { fprintf(stderr, "Cannot open input %s: %s\n", input, strerror(errno)); return 3; } // Error check
        FILE* dst = fopen(output, "wb+");           // Open output (create/overwrite)
        if(!dst) { fprintf(stderr, "Cannot open output %s: %s\n", output, strerror(errno)); fclose(src); return 3; }                    // Error
        char buf[1<<15];                            // 32KB transfer buffer
        size_t r;                                   // Bytes read per iteration
        while( (r = fread(buf, 1, sizeof(buf), src)) > 0 ) { // Loop copying
            if(fwrite(buf, 1, r, dst) != r) {       // Write chunk
                fprintf(stderr, "Copy write error\n"); // Report error
                fclose(src); fclose(dst); return 3; // Cleanup & exit
            }
        }
        fclose(src);                                 // Close input image
        fflush(dst);                                 // Flush output buffers
        fclose(dst);                                 // Close output image
    }
    FILE* fimg = fopen(output, "rb+"); if(!fimg){ fprintf(stderr,"Reopen output failed %s\n", output); return 3; } // Reopen for modification

    superblock_t sb; // Superblock buffer
    if(fseek(fimg, 0, SEEK_SET)!=0 || fread(&sb,1,sizeof(sb),fimg)!=sizeof(sb)){ fprintf(stderr,"Read superblock failed\n"); fclose(fimg); return 4; } // Read superblock
    if(sb.magic != 0x4D565346u || sb.block_size!=BS){ fprintf(stderr,"Bad superblock\n"); fclose(fimg); return 4; } // Validate header

    uint8_t inode_bitmap_block[BS]; // Inode bitmap buffer
    uint8_t data_bitmap_block[BS];  // Data bitmap buffer
    if(fseek(fimg, (long)sb.inode_bitmap_start*BS, SEEK_SET)!=0 || fread(inode_bitmap_block,1,BS,fimg)!=BS){ fprintf(stderr,"Read inode bitmap failed\n"); fclose(fimg); return 4; } // Load inode bitmap
    if(fseek(fimg, (long)sb.data_bitmap_start*BS, SEEK_SET)!=0 || fread(data_bitmap_block,1,BS,fimg)!=BS){ fprintf(stderr,"Read data bitmap failed\n"); fclose(fimg); return 4; } // Load data bitmap

    size_t inode_table_bytes = sb.inode_table_blocks * BS;         // Total inode table bytes
    uint8_t* inode_table = malloc(inode_table_bytes);              // Allocate inode table buffer
    if(!inode_table){ fprintf(stderr,"OOM inode table\n"); fclose(fimg); return 5; } // Check alloc
    if(fseek(fimg, (long)sb.inode_table_start*BS, SEEK_SET)!=0 || fread(inode_table,1,inode_table_bytes,fimg)!=inode_table_bytes){ fprintf(stderr,"Read inode table failed\n"); free(inode_table); fclose(fimg); return 5; } // Load table

    struct stat st; // Host file stat buffer
    if(stat(filepath,&st)!=0){ fprintf(stderr,"Cannot stat %s: %s\n", filepath,strerror(errno)); free(inode_table); fclose(fimg); return 5; } // Stat target file
    if(!S_ISREG(st.st_mode)){ fprintf(stderr,"Not a regular file\n"); free(inode_table); fclose(fimg); return 5; } // Require regular file
    size_t file_size = (size_t)st.st_size; // File size
    if(file_size > 12*BS){ fprintf(stderr,"File too large for MiniVSFS (uses only 12 direct blocks)\n"); } // Warn if truncating

    FILE* ff = fopen(filepath,"rb"); if(!ff){ fprintf(stderr,"Cannot open file %s\n", filepath); free(inode_table); fclose(fimg); return 5; } // Open file
    uint8_t* filebuf = malloc(file_size); if(!filebuf){ fprintf(stderr,"OOM filebuf\n"); fclose(ff); free(inode_table); fclose(fimg); return 5; } // Allocate buffer
    if(fread(filebuf,1,file_size,ff)!=file_size){ fprintf(stderr,"Read file failed\n"); fclose(ff); free(filebuf); free(inode_table); fclose(fimg); return 5; } // Read file
    fclose(ff); // Close host file

    int ino_idx = find_first_zero_bit(inode_bitmap_block, sb.inode_count); // Find free inode slot
    if(ino_idx<0){ fprintf(stderr,"No free inodes\n"); free(filebuf); free(inode_table); fclose(fimg); return 6; } // Abort if full
    set_bit(inode_bitmap_block, ino_idx);        // Mark inode allocated
    uint32_t inode_no = (uint32_t)(ino_idx+1);   // Inode numbers are 1-based

    size_t needed_blocks = (file_size + BS -1)/BS; // Number of blocks needed
    if(needed_blocks > 12) needed_blocks = 12;      // Limit to direct block capacity
    uint32_t dblocks[12]={0}; size_t allocated=0;   // Data block indices & count
    for(size_t i=0;i<sb.data_region_blocks && allocated<needed_blocks;i++){ // Scan data bitmap
        if( (data_bitmap_block[i/8] & (1u<<(i%8)))==0){ // Free block?
            set_bit(data_bitmap_block,i);              // Mark allocated
            dblocks[allocated]=(uint32_t)(sb.data_region_start + i); // Absolute block number
            if(fseek(fimg, (long)( (sb.data_region_start + i) * BS ), SEEK_SET)!=0){ fprintf(stderr,"data block seek fail\n"); free(filebuf); free(inode_table); fclose(fimg); return 7; } // Seek
            size_t copy = (file_size > BS)? BS : file_size; // Bytes to write in this block
            if(fwrite(filebuf + allocated*BS,1,copy,fimg)!=copy){ fprintf(stderr,"data block write fail\n"); free(filebuf); free(inode_table); fclose(fimg); return 7; } // Write data
            if(copy < BS){ size_t zlen = BS - copy; static uint8_t zbuf[BS]; if(fwrite(zbuf,1,zlen,fimg)!=zlen){ fprintf(stderr,"pad write fail\n"); free(filebuf); free(inode_table); fclose(fimg); return 7; } } // Zero pad remainder
            file_size -= copy;                          // Decrease bytes left
            allocated++;                                // Increment allocated count
        }
    }
    free(filebuf); // Release file buffer
    if(allocated==0){ fprintf(stderr,"Failed to allocate data blocks\n"); free(inode_table); fclose(fimg); return 7; } // Ensure at least one block

    inode_t ino; memset(&ino,0,sizeof(ino)); // Initialize new inode
    ino.mode = 0100000;                      // Mark as regular file
    ino.links = 1;                           // One link from directory
    ino.uid=0; ino.gid=0; ino.proj_id=4; ino.uid16_gid16=0; ino.xattr_ptr=0; // Ownership & misc
    ino.size_bytes = (uint64_t)((allocated-1)*BS + ( (st.st_size % BS)? (st.st_size % BS): (allocated?BS:0)) ); // Compute logical size
    ino.atime = ino.mtime = ino.ctime = (uint64_t)time(NULL); // Set timestamps
    for(int i=0;i<12;i++) ino.direct[i]=dblocks[i]; // Copy data block pointers
    inode_crc_finalize(&ino);                       // Compute inode CRC
    memcpy(inode_table + ino_idx*INODE_SIZE, &ino, sizeof(ino)); // Store inode in table

    inode_t root; memcpy(&root, inode_table + 0*INODE_SIZE, sizeof(root)); // Load root inode
    uint32_t root_first_block_abs = root.direct[0]; // Root dir first data block
    if(root_first_block_abs != sb.data_region_start){ /* still ok */ } // Sanity (non-fatal)
    uint64_t root_block_index = root_first_block_abs - sb.data_region_start; // Relative index
    dirent64_t dirblock_local[BS/sizeof(dirent64_t)]; // Directory block buffer
    if(fseek(fimg, (long)( (sb.data_region_start + root_block_index) * BS ), SEEK_SET)!=0 || fread(dirblock_local,1,BS,fimg)!=BS){ fprintf(stderr,"Read root dir block failed\n"); free(inode_table); fclose(fimg); return 8; } // Read directory
    dirent64_t* dirblock = dirblock_local; // Pointer alias
    int placed=0;                           // Flag if entry inserted
    for(int i=0;i< (int)(BS/sizeof(dirent64_t)); i++){ // Scan directory entries
        if(dirblock[i].inode_no==0){        // Free slot found
            dirblock[i].inode_no = inode_no; // Set inode reference
            dirblock[i].type = 1;           // Mark as file
            memset(dirblock[i].name,0,sizeof(dirblock[i].name)); // Clear name field
            const char* base = strrchr(filepath,'/'); base = base? base+1: filepath; // Extract basename
            size_t blen = strlen(base);     // Name length
            if(blen > sizeof(dirblock[i].name)-1) blen = sizeof(dirblock[i].name)-1; // Truncate
            memcpy(dirblock[i].name, base, blen); // Copy name
            dirent_checksum_finalize(&dirblock[i]); // Compute checksum
            placed=1; break;                // Done
        }
    }
    if(!placed){ fprintf(stderr,"Root directory full (single block limit)\n"); free(inode_table); fclose(fimg); return 8; } // Fail if no slot
    if(fseek(fimg, (long)( (sb.data_region_start + root_block_index) * BS ), SEEK_SET)!=0 || fwrite(dirblock,1,BS,fimg)!=BS){ fprintf(stderr,"Write root dir block failed\n"); free(inode_table); fclose(fimg); return 8; } // Write directory back
    root.links += 1; // Increment root link count for new file's name
    inode_crc_finalize(&root); memcpy(inode_table + 0*INODE_SIZE, &root, sizeof(root)); // Update root inode

    sb.mtime_epoch = (uint64_t)time(NULL); // Update FS modified time
    superblock_crc_finalize(&sb);          // Recompute superblock CRC
    if(fseek(fimg, (long)sb.inode_bitmap_start*BS, SEEK_SET)!=0 || fwrite(inode_bitmap_block,1,BS,fimg)!=BS){ fprintf(stderr,"Write inode bitmap failed\n"); free(inode_table); fclose(fimg); return 9; } // Write inode bitmap
    if(fseek(fimg, (long)sb.data_bitmap_start*BS, SEEK_SET)!=0 || fwrite(data_bitmap_block,1,BS,fimg)!=BS){ fprintf(stderr,"Write data bitmap failed\n"); free(inode_table); fclose(fimg); return 9; } // Write data bitmap
    if(fseek(fimg, (long)sb.inode_table_start*BS, SEEK_SET)!=0 || fwrite(inode_table,1,inode_table_bytes,fimg)!=inode_table_bytes){ fprintf(stderr,"Write inode table failed\n"); free(inode_table); fclose(fimg); return 9; } // Write inode table
    if(fseek(fimg,0,SEEK_SET)!=0 || fwrite(&sb,1,sizeof(sb),fimg)!=sizeof(sb)){ fprintf(stderr,"Write superblock failed\n"); free(inode_table); fclose(fimg); return 9; } // Write superblock
    fflush(fimg); // Flush file buffers
    fclose(fimg); // Close image
    fprintf(stdout, "Added file to image as inode %u -> %s\n", inode_no, output); // Status output
    free(inode_table); // Free inode table buffer
    return 0; // Success
}
