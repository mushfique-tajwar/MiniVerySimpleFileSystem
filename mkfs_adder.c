#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#define BS 4096u
#define INODE_SIZE 128u
#define ROOT_INO 1u
#define DIRECT_MAX 12
#pragma pack(push, 1)

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t block_size;
    uint64_t total_blocks;
    uint64_t inode_count;
    uint64_t inode_bitmap_start;
    uint64_t inode_bitmap_blocks;
    uint64_t data_bitmap_start;
    uint64_t data_bitmap_blocks;
    uint64_t inode_table_start;
    uint64_t inode_table_blocks;
    uint64_t data_region_start;
    uint64_t data_region_blocks;
    uint64_t root_inode;
    uint64_t mtime_epoch;
    uint32_t flags;
    uint32_t checksum;            // crc32(superblock[0..4091])
} superblock_t;
#pragma pack(pop)
_Static_assert(sizeof(superblock_t) == 116, "superblock must fit in one block");

#pragma pack(push,1)
typedef struct {
    uint16_t mode;
    uint16_t links;
    uint32_t uid;
    uint32_t gid;
    uint64_t size_bytes;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t direct[12];
    uint32_t reserved_0;
    uint32_t reserved_1;
    uint32_t reserved_2;
    uint32_t proj_id;
    uint32_t uid16_gid16;
    uint64_t xattr_ptr;
    uint64_t inode_crc;   // low 4 bytes store crc32 of bytes [0..119]; high 4 bytes 0
} inode_t;
#pragma pack(pop)
_Static_assert(sizeof(inode_t)==INODE_SIZE, "inode size mismatch");

#pragma pack(push,1)
typedef struct {
    uint32_t inode_no;
    uint8_t  type;
    char     name[58];
    uint8_t  checksum; // XOR of bytes 0..62
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

static void usage(const char* prog){
    fprintf(stderr, "Usage: %s --input <in.img> --output <out.img> --file <path>\n", prog);
}

static void set_bit(uint8_t* bm, uint64_t idx){ bm[idx/8] |= (uint8_t)(1u<<(idx%8)); }

static int find_first_zero_bit(uint8_t* bm, uint64_t max_bits){
    for(uint64_t i=0;i<max_bits;i++){
        if( (bm[i/8] & (1u<<(i%8))) == 0){
            return (int)i;
        }
    }
    return -1;
}

int main(int argc, char** argv) {
    crc32_init();
    const char *input=NULL,*output=NULL,*filepath=NULL;
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--input")==0 && i+1<argc) input=argv[++i];
        else if(strcmp(argv[i],"--output")==0 && i+1<argc) output=argv[++i];
        else if(strcmp(argv[i],"--file")==0 && i+1<argc) filepath=argv[++i];
        else if(strcmp(argv[i],"--help")==0){ usage(argv[0]); return 0; }
        else { fprintf(stderr,"Unknown/incomplete argument %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if(!input || !output || !filepath) {
        usage(argv[0]);
        return 2;
    }

    {
        FILE* src = fopen(input, "rb");
        if(!src) {
            fprintf(stderr, "Cannot open input %s: %s\n", input, strerror(errno));
            return 3;
        }
        FILE* dst = fopen(output, "wb+");
        if(!dst) {
            fprintf(stderr, "Cannot open output %s: %s\n", output, strerror(errno));
            fclose(src);
            return 3;
        }
        char buf[1<<15];
        size_t r;
        while( (r = fread(buf, 1, sizeof(buf), src)) > 0 ) {
            if(fwrite(buf, 1, r, dst) != r) {
                fprintf(stderr, "Copy write error\n");
                fclose(src);
                fclose(dst);
                return 3;
            }
        }
        fclose(src);
        fflush(dst);
        fclose(dst);
    }
    FILE* fimg = fopen(output, "rb+");
    if(!fimg) {
        fprintf(stderr, "Reopen output failed %s\n", output);
        return 3;
    }

    superblock_t sb;
    if(fseek(fimg, 0, SEEK_SET) != 0 || fread(&sb, 1, sizeof(sb), fimg) != sizeof(sb)) {
        fprintf(stderr, "Read superblock failed\n");
        fclose(fimg);
        return 4;
    }
    if(sb.magic != 0x4D565346u || sb.block_size != BS) {
        fprintf(stderr, "Bad superblock\n");
        fclose(fimg);
        return 4;
    }

    uint8_t inode_bitmap_block[BS];
    uint8_t data_bitmap_block[BS];
    if(fseek(fimg, (long)sb.inode_bitmap_start * BS, SEEK_SET) != 0 || fread(inode_bitmap_block, 1, BS, fimg) != BS) {
        fprintf(stderr, "Read inode bitmap failed\n");
        fclose(fimg);
        return 4;
    }
    if(fseek(fimg, (long)sb.data_bitmap_start * BS, SEEK_SET) != 0 || fread(data_bitmap_block, 1, BS, fimg) != BS) {
        fprintf(stderr, "Read data bitmap failed\n");
        fclose(fimg);
        return 4;
    }

    size_t inode_table_bytes = sb.inode_table_blocks * BS;
    uint8_t* inode_table = malloc(inode_table_bytes);
    if(!inode_table) {
        fprintf(stderr, "OOM inode table\n");
        fclose(fimg);
        return 5;
    }
    if(fseek(fimg, (long)sb.inode_table_start * BS, SEEK_SET) != 0 || fread(inode_table, 1, inode_table_bytes, fimg) != inode_table_bytes) {
        fprintf(stderr, "Read inode table failed\n");
        free(inode_table);
        fclose(fimg);
        return 5;
    }

    struct stat st;
    if(stat(filepath, &st) != 0) {
        fprintf(stderr, "Cannot stat %s: %s\n", filepath, strerror(errno));
        free(inode_table);
        fclose(fimg);
        return 5;
    }
    if(!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Not a regular file\n");
        free(inode_table);
        fclose(fimg);
        return 5;
    }
    size_t file_size = (size_t)st.st_size;
    if(file_size > 12*BS){ fprintf(stderr,"File too large for MiniVSFS (uses only 12 direct blocks)\n"); }

    FILE* ff = fopen(filepath, "rb");
    if(!ff) {
        fprintf(stderr, "Cannot open file %s\n", filepath);
        free(inode_table);
        fclose(fimg);
        return 5;
    }
    uint8_t* filebuf = malloc(file_size);
    if(!filebuf) {
        fprintf(stderr, "OOM filebuf\n");
        fclose(ff);
        free(inode_table);
        fclose(fimg);
        return 5;
    }
    if(fread(filebuf, 1, file_size, ff) != file_size) {
        fprintf(stderr, "Read file failed\n");
        fclose(ff);
        free(filebuf);
        free(inode_table);
        fclose(fimg);
        return 5;
    }
    fclose(ff);


    int ino_idx = find_first_zero_bit(inode_bitmap_block, sb.inode_count);
    if(ino_idx < 0) {
        fprintf(stderr, "No free inodes\n");
        free(filebuf);
        free(inode_table);
        fclose(fimg);
        return 6;
    }
    set_bit(inode_bitmap_block, ino_idx);
    uint32_t inode_no = (uint32_t)(ino_idx + 1);

    
    size_t needed_blocks = (file_size + BS - 1) / BS;
    if(needed_blocks > 12) {
        needed_blocks = 12;
    }
    uint32_t dblocks[12] = {0};
    size_t allocated = 0;
    for(size_t i = 0; i < sb.data_region_blocks && allocated < needed_blocks; i++) {
        if( (data_bitmap_block[i/8] & (1u << (i%8))) == 0 ) {
            set_bit(data_bitmap_block, i);
            dblocks[allocated] = (uint32_t)(sb.data_region_start + i);
            if(fseek(fimg, (long)((sb.data_region_start + i) * BS), SEEK_SET) != 0) {
                fprintf(stderr, "data block seek fail\n");
                free(filebuf);
                free(inode_table);
                fclose(fimg);
                return 7;
            }
            size_t copy = (file_size > BS) ? BS : file_size;
            if(fwrite(filebuf + allocated * BS, 1, copy, fimg) != copy) {
                fprintf(stderr, "data block write fail\n");
                free(filebuf);
                free(inode_table);
                fclose(fimg);
                return 7;
            }
            if(copy < BS) {
                size_t zlen = BS - copy;
                static uint8_t zbuf[BS];
                if(fwrite(zbuf, 1, zlen, fimg) != zlen) {
                    fprintf(stderr, "pad write fail\n");
                    free(filebuf);
                    free(inode_table);
                    fclose(fimg);
                    return 7;
                }
            }
            file_size -= copy;
            allocated++;
        }
    }
    free(filebuf);
    if(allocated == 0) {
        fprintf(stderr, "Failed to allocate data blocks\n");
        free(inode_table);
        fclose(fimg);
        return 7;
    }

    inode_t ino;
    memset(&ino, 0, sizeof(ino));
    ino.mode = 0100000;
    ino.links = 1;
    ino.uid = 0;
    ino.gid = 0;
    ino.proj_id = 4;
    ino.uid16_gid16 = 0;
    ino.xattr_ptr = 0;
    ino.size_bytes = (uint64_t)((allocated - 1) * BS + ( (st.st_size % BS) ? (st.st_size % BS) : (allocated ? BS : 0)) );
    ino.atime = (uint64_t)time(NULL);
    ino.mtime = ino.atime;
    ino.ctime = ino.atime;
    for(int i = 0; i < 12; i++) {
        ino.direct[i] = dblocks[i];
    }
    inode_crc_finalize(&ino);
    memcpy(inode_table + ino_idx*INODE_SIZE, &ino, sizeof(ino));

    inode_t root;
    memcpy(&root, inode_table + 0 * INODE_SIZE, sizeof(root));
    uint32_t root_first_block_abs = root.direct[0];
    if(root_first_block_abs != sb.data_region_start){ /* still ok, just compute offset */ }
    uint64_t root_block_index = root_first_block_abs - sb.data_region_start;
    dirent64_t dirblock_local[BS/sizeof(dirent64_t)];
    if(fseek(fimg, (long)((sb.data_region_start + root_block_index) * BS), SEEK_SET) != 0 || fread(dirblock_local, 1, BS, fimg) != BS) {
        fprintf(stderr, "Read root dir block failed\n");
        free(inode_table);
        fclose(fimg);
        return 8;
    }
    dirent64_t* dirblock = dirblock_local;
    int placed=0;
    for(int i = 0; i < (int)(BS / sizeof(dirent64_t)); i++) {
        if(dirblock[i].inode_no == 0) {
            dirblock[i].inode_no = inode_no;
            dirblock[i].type = 1; // file
            memset(dirblock[i].name, 0, sizeof(dirblock[i].name));
            const char* base = strrchr(filepath, '/');
            base = base ? base + 1 : filepath;
            size_t blen = strlen(base);
            if(blen > sizeof(dirblock[i].name) - 1) {
                blen = sizeof(dirblock[i].name) - 1;
            }
            memcpy(dirblock[i].name, base, blen);
            dirent_checksum_finalize(&dirblock[i]);
            placed = 1;
            break;
        }
    }
    if(!placed) {
        fprintf(stderr, "Root directory full (single block limit)\n");
        free(inode_table);
        fclose(fimg);
        return 8;
    }
    if(fseek(fimg, (long)((sb.data_region_start + root_block_index) * BS), SEEK_SET) != 0 || fwrite(dirblock, 1, BS, fimg) != BS) {
        fprintf(stderr, "Write root dir block failed\n");
        free(inode_table);
        fclose(fimg);
        return 8;
    }
    root.links += 1;
    inode_crc_finalize(&root); memcpy(inode_table + 0*INODE_SIZE, &root, sizeof(root));

    sb.mtime_epoch = (uint64_t)time(NULL);
    superblock_crc_finalize(&sb);
    if(fseek(fimg, (long)sb.inode_bitmap_start * BS, SEEK_SET) != 0 || fwrite(inode_bitmap_block, 1, BS, fimg) != BS) {
        fprintf(stderr, "Write inode bitmap failed\n");
        free(inode_table);
        fclose(fimg);
        return 9;
    }
    if(fseek(fimg, (long)sb.data_bitmap_start * BS, SEEK_SET) != 0 || fwrite(data_bitmap_block, 1, BS, fimg) != BS) {
        fprintf(stderr, "Write data bitmap failed\n");
        free(inode_table);
        fclose(fimg);
        return 9;
    }
    if(fseek(fimg, (long)sb.inode_table_start * BS, SEEK_SET) != 0 || fwrite(inode_table, 1, inode_table_bytes, fimg) != inode_table_bytes) {
        fprintf(stderr, "Write inode table failed\n");
        free(inode_table);
        fclose(fimg);
        return 9;
    }
    if(fseek(fimg, 0, SEEK_SET) != 0 || fwrite(&sb, 1, sizeof(sb), fimg) != sizeof(sb)) {
        fprintf(stderr, "Write superblock failed\n");
        free(inode_table);
        fclose(fimg);
        return 9;
    }
    fflush(fimg);
    fclose(fimg);
    fprintf(stdout, "Added file to image as inode %u -> %s\n", inode_no, output);
    free(inode_table);
    return 0;
}
