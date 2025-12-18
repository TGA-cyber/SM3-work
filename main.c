#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SM3_BLOCK_SIZE 64
#define SM3_HASH_SIZE 32
#define INPUT_BUFFER_SIZE 1024

// 初始向量
static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 循环左移宏
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 布尔函数
static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return j < 16 ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return j < 16 ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

// 置换函数
static uint32_t P0(uint32_t x) { return x ^ ROTL(x, 9) ^ ROTL(x, 17); }
static uint32_t P1(uint32_t x) { return x ^ ROTL(x, 15) ^ ROTL(x, 23); }

// 消息填充
int sm3_padding(const uint8_t* msg, size_t len, uint8_t** out, size_t* out_len) {
    size_t bit_len = len * 8;
    size_t pad_len = ((len + 9) + (SM3_BLOCK_SIZE - 1)) & ~(SM3_BLOCK_SIZE - 1);

    *out = malloc(pad_len);
    if (!*out) return -1;

    memcpy(*out, msg, len);
    (*out)[len] = 0x80;
    memset(*out + len + 1, 0, pad_len - len - 9);

    // 大端序添加长度
    for (int i = 0; i < 8; i++)
        (*out)[pad_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;

    *out_len = pad_len;
    return 0;
}

// 消息扩展
void message_expansion(const uint8_t* block, uint32_t W[68], uint32_t W1[64]) {
    // 块转字
    for (int i = 0; i < 16; i++) {
        W[i] = (block[i*4]<<24) | (block[i*4+1]<<16) | (block[i*4+2]<<8) | block[i*4+3];
    }

    // 扩展
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }

    // 计算W1
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
}

// 压缩函数
void compress(uint32_t state[8], const uint8_t* block) {
    uint32_t W[68], W1[64];
    message_expansion(block, W, W1);

    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    for (int j = 0; j < 64; j++) {
        uint32_t Tj = j < 16 ? 0x79CC4519 : 0x7A879D8A;

        uint32_t SS1 = ROTL(ROTL(A, 12) + E + ROTL(Tj, j), 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// SM3哈希
int sm3_hash(const uint8_t* msg, size_t len, uint8_t* hash) {
    uint8_t* padded_msg;
    size_t padded_len;

    if (sm3_padding(msg, len, &padded_msg, &padded_len) != 0) return -1;

    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));

    for (size_t i = 0; i < padded_len; i += SM3_BLOCK_SIZE)
        compress(state, padded_msg + i);

    // 输出哈希值
    for (int i = 0; i < 8; i++) {
        hash[i*4]     = state[i] >> 24;
        hash[i*4 + 1] = state[i] >> 16;
        hash[i*4 + 2] = state[i] >> 8;
        hash[i*4 + 3] = state[i];
    }

    free(padded_msg);
    return 0;
}

// 打印哈希值
void print_hash(const uint8_t* hash) {
    for (int i = 0; i < SM3_HASH_SIZE; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

// 主函数
int main() {
    printf("SM3哈希算法\n===========\n\n请输入要计算哈希的明文: ");

    char input[INPUT_BUFFER_SIZE];
    if (!fgets(input, sizeof(input), stdin)) {
        fprintf(stderr, "读取输入失败\n");
        return 1;
    }

    // 移除换行符
    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n')
        input[--len] = '\0';

    uint8_t hash[SM3_HASH_SIZE];

    if (sm3_hash((uint8_t*)input, len, hash) == 0) {
        printf("\n输入明文: %s\nSM3哈希值: ", input);
        print_hash(hash);
    } else {
        fprintf(stderr, "哈希计算失败\n");
        return 1;
    }

    return 0;
}
