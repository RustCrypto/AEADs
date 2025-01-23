#include <stdio.h>

/*
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 12
#define CRYPTO_ABYTES 16
*/

/* Exactly one of the following should be set */
#define HS1_SIV_LO  0
#define HS1_SIV     1
#define HS1_SIV_HI  0

#define CRYPTO_KEYBYTES 32
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 12
#if HS1_SIV_LO
# define CRYPTO_ABYTES 8
#elif HS1_SIV
# define CRYPTO_ABYTES 16
#elif HS1_SIV_HI
# define CRYPTO_ABYTES 32
#else
# error "one of HS_SIV, HS_SIV_LO or HS_SIV_HI must be 1"
#endif

#include "encrypt.c"

#if CRYPTO_ABYTES != HS1_SIV_SIV_LEN
# error "CRYPTO_ABYTES must equal HS1_SIV_SIV_LEN"
#endif

#define MSG "Hello to the entire wide, round, global globe!"
#define MSG64 "Hello to the entire wide, round, global globe!!! okookokokokokok"
//#define MSG ""
#define KEY "Short keys? Use long for testing"
#define NONCE "Quack quack!"

void hs1siv_subkeygen(hs1siv_ctx_t *ctx, void *user_key, unsigned key_bytes);

void print_bytes(const unsigned char *bytes, unsigned long long len, unsigned long long wrap) {
    for (unsigned long long i = 0; i < len; i++) {
        printf("0x%02x,", bytes[i]);
        if (i % wrap == wrap - 1)
            printf("\n");
    }
    if (len % wrap != 0)
        printf("\n");
}

void print_words(const uint32_t *words, unsigned long long len, unsigned long long wrap) {
    for (unsigned long long i = 0; i < len; i++) {
        printf("0x%08x,", words[i]);
        if (i % wrap == wrap - 1)
            printf("\n");
    }
    if (len % wrap != 0)
        printf("\n");
}

void print_doubles(const uint64_t *doubles, unsigned long long len, unsigned long long wrap) {
    for (unsigned long long i = 0; i < len; i++) {
        printf("0x%016llx,", doubles[i]);
        if (i % wrap == wrap - 1)
            printf("\n");
    }
    if (len % wrap != 0)
        printf("\n");
}

void subkeygen(hs1siv_ctx_t *ctx) {
    hs1siv_subkeygen(ctx, KEY, sizeof(KEY) - 1);
    printf("chacha_key:\n");
    print_bytes(ctx->chacha_key, sizeof(ctx->chacha_key), 8);
    printf("nh_key:\n");
    print_words((void *)ctx->nh_key, sizeof(ctx->nh_key) / 4, 2);
    printf("poly_key:\n");
    print_doubles((void *)ctx->poly_key, sizeof(ctx->poly_key) / 8, 1);
#if (HS1_SIV_HASH_RNDS > 4)
    printf("asu_key:\n");
    print_doubles((void *)ctx->asu_key, sizeof(ctx->asu_key) / 8, 1);
#endif
}

void hash(hs1siv_ctx_t *ctx) {
    #if (HS1_SIV_HASH_RNDS > 4)
    uint64_t h[HS1_SIV_HASH_RNDS/2];
    #else
    uint64_t h[HS1_SIV_HASH_RNDS];
    #endif
    hs1_hash(ctx, MSG, sizeof(MSG) - 1, h);
    printf("h:\n");
#if (HS1_SIV_HASH_RNDS > 4)
    print_words((uint32_t *)h, sizeof(h) / 4, 1);
#else
    print_doubles(h, sizeof(h) / 8, 1);
#endif
}

void ciphertext(void) {
	unsigned char cbuf[1024];
	unsigned long long clen;

	crypto_aead_encrypt(
        cbuf, &clen, 
        MSG, sizeof(MSG) - 1,
        "", 0,
        (void *)0,
        NONCE,
        KEY
    );

    printf("ciphertext length: %llu\n", clen);
    print_bytes(cbuf, clen, 8);
}

int main() {
    hs1siv_ctx_t ctx;
    subkeygen(&ctx);
    hash(&ctx);
    ciphertext();
    return 0;
}
