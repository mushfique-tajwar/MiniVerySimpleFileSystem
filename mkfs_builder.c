// Build: gcc -O2 -std=c17 -Wall -Wextra mkfs_builder_skeleton.c -o mkfs_builder
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>

#define BS 4096u               // block size
#define INODE_SIZE 128u
#define ROOT_INO 1u

uint64_t g_random_seed = 0; // This should be replaced by seed value from the CLI.

// below contains some basic structures you need for your project
// you are free to create more structures as you require

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;              // 0x4D565346 ("MVSF")
    uint32_t version;            // 1
    uint32_t block_size;         // 4096
    uint64_t total_blocks;       // size_kib*1024/4096
    uint64_t inode_count;        // from cli
    uint64_t inode_bitmap_start; // absolute block numbers
    uint64_t inode_bitmap_blocks;// =1
    uint64_t data_bitmap_start;  // absolute block numbers
    uint64_t data_bitmap_blocks; // =1
    uint64_t inode_table_start;  // after bitmaps
    uint64_t inode_table_blocks; // ceil(inode_count*INODE_SIZE/BS)
    uint64_t data_region_start;  // after inode table
    uint64_t data_region_blocks; // remaining blocks
    uint64_t root_inode;         // =1
    uint64_t mtime_epoch;        // build time
    uint32_t flags;              // 0
    uint32_t checksum;           // crc32(superblock[0..4091]) -- last
} superblock_t;
#pragma pack(pop)
_Static_assert(sizeof(superblock_t) == 116, "superblock must fit in one block");

#pragma pack(push,1)
typedef struct {
    uint16_t mode;          // file/dir mode bits (octal)
    uint16_t links;         // link count
    uint32_t uid;           // 0
    uint32_t gid;           // 0
    uint64_t size_bytes;    // file size
    uint64_t atime;         // access time
    uint64_t mtime;         // modification time
    uint64_t ctime;         // change time
    uint32_t direct[12];    // direct block pointers (absolute blocks)
    uint32_t reserved_0;    // 0
    uint32_t reserved_1;    // 0
    uint32_t reserved_2;    // 0
    uint32_t proj_id;       // group id = 4 used in the main
    uint32_t uid16_gid16;   // 0
    uint64_t xattr_ptr;     // 0
    uint64_t inode_crc;     // low 4 bytes store crc32 of bytes [0..119]; high 4 bytes 0
} inode_t;
#pragma pack(pop)
_Static_assert(sizeof(inode_t)==INODE_SIZE, "inode size mismatch");

#pragma pack(push,1)
typedef struct {
    uint32_t inode_no;          // 0 if free
    uint8_t  type;              // 1=file,2=dir
    char     name[58];          // not necessarily null-terminated; zero padded
    uint8_t  checksum;          // XOR of bytes 0..62
} dirent64_t;
#pragma pack(pop)
_Static_assert(sizeof(dirent64_t)==64, "dirent size mismatch");


// ==========================DO NOT CHANGE THIS PORTION=========================
// These functions are there for your help. You should refer to the specifications to see how you can use them.
// ====================================CRC32====================================
uint32_t CRC32_TAB[256];
void crc32_init(void){
    for (uint32_t i=0;i<256;i++){
        uint32_t c=i;
        for(int j=0;j<8;j++) c = (c&1)?(0xEDB88320u^(c>>1)):(c>>1);
        CRC32_TAB[i]=c;
    }
}
uint32_t crc32(const void* data, size_t n){
    const uint8_t* p=(const uint8_t*)data; uint32_t c=0xFFFFFFFFu;
    for(size_t i=0;i<n;i++) c = CRC32_TAB[(c^p[i])&0xFF] ^ (c>>8);
    return c ^ 0xFFFFFFFFu;
}
// ====================================CRC32====================================

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
static uint32_t superblock_crc_finalize(superblock_t *sb) {
    sb->checksum = 0;
    uint32_t s = crc32((void *) sb, BS - 4);
    sb->checksum = s;
    return s;
}

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
void inode_crc_finalize(inode_t* ino){
    uint8_t tmp[INODE_SIZE]; memcpy(tmp, ino, INODE_SIZE);
    // zero crc area before computing
    memset(&tmp[120], 0, 8);
    uint32_t c = crc32(tmp, 120);
    ino->inode_crc = (uint64_t)c; // low 4 bytes carry the crc
}

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
void dirent_checksum_finalize(dirent64_t* de) {
    const uint8_t* p = (const uint8_t*)de;
    uint8_t x = 0;
    for (int i = 0; i < 63; i++) x ^= p[i];   // covers ino(4) + type(1) + name(58)
    de->checksum = x;
}

// =========================== Helpers =============================
static void usage(const char* prog){
    fprintf(stderr, "Usage: %s --image <out.img> --size-kib <180..4096 multiple of 4> --inodes <128..512> [--seed <n>]\n", prog);
}

static int parse_u64(const char* s, uint64_t* out){
    if(!s || !*s) {
        return -1;
    }
    char* end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if(errno || *end != '\0') {
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

static void set_bit(uint8_t* bm, uint64_t idx){
    bm[idx/8] |= (uint8_t)(1u << (idx%8));
}

int main(int argc, char** argv) {
    crc32_init();
    const char* image_path=NULL; uint64_t size_kib=0; uint64_t inode_count=0; uint64_t seed=0; int have_seed=0;
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--image")==0 && i+1<argc){ image_path=argv[++i]; }
        else if(strcmp(argv[i],"--size-kib")==0 && i+1<argc){ if(parse_u64(argv[++i], &size_kib)){ fprintf(stderr,"Invalid --size-kib\n"); return 2;} }
        else if(strcmp(argv[i],"--inodes")==0 && i+1<argc){ if(parse_u64(argv[++i], &inode_count)){ fprintf(stderr,"Invalid --inodes\n"); return 2;} }
        else if(strcmp(argv[i],"--seed")==0 && i+1<argc){ if(parse_u64(argv[++i], &seed)){ fprintf(stderr,"Invalid --seed\n"); return 2;} have_seed=1; }
        else if(strcmp(argv[i],"--help")==0){ usage(argv[0]); return 0; }
        else { fprintf(stderr,"Unknown or incomplete argument: %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if(!image_path || !size_kib || !inode_count){ usage(argv[0]); return 2; }
    if(size_kib < 180 || size_kib > 4096 || (size_kib % 4)!=0){ fprintf(stderr,"size-kib out of range or not multiple of 4\n"); return 2; }
    if(inode_count < 128 || inode_count > 512){ fprintf(stderr,"inodes out of range\n"); return 2; }
    g_random_seed = have_seed ? seed : (uint64_t)time(NULL);

    uint64_t total_blocks = (size_kib*1024ull)/BS; // guaranteed integer
    // layout: [0] superblock, [1] inode bitmap, [2] data bitmap, [3..] inode table, then data
    uint64_t inode_table_bytes = inode_count * INODE_SIZE;
    uint64_t inode_table_blocks = (inode_table_bytes + BS -1)/BS;
    if(inode_table_blocks==0) inode_table_blocks=1; // should not happen
    uint64_t used_meta = 1 + 1 + 1 + inode_table_blocks;
    if(used_meta >= total_blocks){ fprintf(stderr,"Insufficient blocks for metadata layout\n"); return 3; }
    uint64_t data_region_blocks = total_blocks - used_meta;
    if(data_region_blocks==0){ fprintf(stderr,"No data blocks available\n"); return 3; }

    superblock_t sb; memset(&sb,0,sizeof(sb));
    sb.magic = 0x4D565346u; // 'MVSF'
    sb.version = 1;
    sb.block_size = BS;
    sb.total_blocks = total_blocks;
    sb.inode_count = inode_count;
    sb.inode_bitmap_start = 1;
    sb.inode_bitmap_blocks = 1;
    sb.data_bitmap_start = 2;
    sb.data_bitmap_blocks = 1;
    sb.inode_table_start = 3;
    sb.inode_table_blocks = inode_table_blocks;
    sb.data_region_start = sb.inode_table_start + sb.inode_table_blocks;
    sb.data_region_blocks = data_region_blocks;
    sb.root_inode = ROOT_INO;
    sb.mtime_epoch = (uint64_t)time(NULL);
    sb.flags = 0;
    superblock_crc_finalize(&sb);

    // allocate buffers
    uint8_t* inode_bitmap = calloc(1, BS);
    uint8_t* data_bitmap  = calloc(1, BS);
    if(!inode_bitmap||!data_bitmap){ fprintf(stderr,"OOM\n"); return 5; }

    // mark root inode (index 0 -> inode #1)
    set_bit(inode_bitmap, 0);
    // mark first data block used for root directory (data block index 0)
    set_bit(data_bitmap, 0);

    // inode table buffer
    uint64_t it_bytes = inode_table_blocks * BS;
    uint8_t* inode_table = calloc(1, it_bytes);
    if(!inode_table){ fprintf(stderr,"OOM inode table\n"); return 5; }

    // create root inode at index 0
    inode_t root; memset(&root,0,sizeof(root));
    root.mode = 0040000; // directory
    root.links = 2; // . and ..
    root.uid = 0; root.gid=0; root.proj_id=4; root.uid16_gid16=0; root.xattr_ptr=0;
    root.size_bytes = 128; // two entries
    root.atime = root.mtime = root.ctime = sb.mtime_epoch;
    root.direct[0] = (uint32_t)sb.data_region_start; // first data block absolute
    for(int i=1;i<12;i++) root.direct[i]=0;
    inode_crc_finalize(&root);
    memcpy(inode_table, &root, sizeof(root));

    // data region: create first data block for root directory
    uint64_t data_bytes = data_region_blocks * BS;
    uint8_t* data_region = calloc(1, data_bytes);
    if(!data_region){ fprintf(stderr,"OOM data region\n"); return 5; }
    // root directory stored in first block of data region (offset 0)
    dirent64_t de; memset(&de,0,sizeof(de));
    // '.'
    de.inode_no = ROOT_INO; de.type = 2; memset(de.name,0,sizeof(de.name)); de.name[0]='.'; dirent_checksum_finalize(&de); memcpy(data_region, &de, sizeof(de));
    // '..'
    memset(&de,0,sizeof(de)); de.inode_no=ROOT_INO; de.type=2; memset(de.name,0,sizeof(de.name)); de.name[0]='.'; de.name[1]='.'; dirent_checksum_finalize(&de); memcpy(data_region+64, &de, sizeof(de));
    // rest already zeroed

    FILE* f = fopen(image_path,"wb+");
    if(!f){ fprintf(stderr,"Cannot open output image %s: %s\n", image_path, strerror(errno)); return 6; }
    // Pre-size the file: seek to last byte then write a zero so random seeks are safe
    if(fseek(f, (long)(total_blocks*BS) - 1, SEEK_SET)!=0){ fprintf(stderr,"fseek size prep failed\n"); return 7; }
    if(fwrite("\0",1,1,f)!=1){ fprintf(stderr,"size extend write failed\n"); return 7; }

    // helper lambda-like macro to write a full block-aligned region
    #define WRITE_AT_BLOCK(block_index, buf, len_desc, expected_bytes) do { \
        if(fseek(f, (long)(block_index)*BS, SEEK_SET)!=0){ fprintf(stderr,"fseek failed for %s (block %llu)\n", len_desc, (unsigned long long)(block_index)); return 7; } \
        if(fwrite(buf,1,expected_bytes,f)!=(size_t)expected_bytes){ fprintf(stderr,"fwrite failed for %s\n", len_desc); return 7; } \
    } while(0)

    // superblock (single block)
    uint8_t sb_block[BS]; memset(sb_block,0,sizeof(sb_block)); memcpy(sb_block,&sb,sizeof(sb));
    WRITE_AT_BLOCK(0, sb_block, "superblock", BS);
    // inode bitmap
    WRITE_AT_BLOCK(sb.inode_bitmap_start, inode_bitmap, "inode bitmap", BS);
    // data bitmap
    WRITE_AT_BLOCK(sb.data_bitmap_start, data_bitmap, "data bitmap", BS);
    // inode table blocks (may span multiple blocks); write sequential blocks from the buffer
    for(uint64_t b=0;b<inode_table_blocks;b++){
        WRITE_AT_BLOCK(sb.inode_table_start + b, inode_table + b*BS, "inode table block", BS);
    }
    // data region blocks
    for(uint64_t b=0;b<data_region_blocks;b++){
        WRITE_AT_BLOCK(sb.data_region_start + b, data_region + b*BS, "data region block", BS);
    }
    #undef WRITE_AT_BLOCK
    fflush(f);
    fclose(f);

    // clean up
    free(inode_bitmap); free(data_bitmap); free(inode_table); free(data_region);
    fprintf(stdout, "Created MiniVSFS image %s: blocks=%" PRIu64 ", inodes=%" PRIu64 ", data_blocks=%" PRIu64 "\n", image_path, total_blocks, inode_count, data_region_blocks);
    return 0;
}
