#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define IMAGE_IN   "images/input.jpeg"
#define IMAGE_ENC  "images/encrypted.bin"
#define IMAGE_DEC  "images/decrypted.jpeg"

// AES Encrypt/Decrypt helper
int aes_crypt(unsigned char *in, int in_len, unsigned char *key,
              unsigned char *iv, unsigned char *out, int do_encrypt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, out_len;

    EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv, do_encrypt);
    EVP_CipherUpdate(ctx, out, &len, in, in_len);
    out_len = len;

    EVP_CipherFinal_ex(ctx, out + len, &len);
    out_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

// Load file into memory
unsigned char *load_file(const char *filename, long *len) {
    FILE *f = fopen(filename, "rb");
    if (!f) { perror("fopen"); return NULL; }
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(*len);
    fread(buf, 1, *len, f);
    fclose(f);
    return buf;
}

// Save memory to file
void save_file(const char *filename, unsigned char *buf, long len) {
    FILE *f = fopen(filename, "wb");
    fwrite(buf, 1, len, f);
    fclose(f);
}

// Run Kyber with given variant
void run_kyber_variant(const char *alg, unsigned char *img_data, long img_len) {
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (kem == NULL) {
        printf("ERROR: Could not init %s\n", alg);
        return;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    printf("\n🔑 Running %s\n", alg);
    printf("   Public key length   : %zu bytes\n", kem->length_public_key);
    printf("   Secret key length   : %zu bytes\n", kem->length_secret_key);
    printf("   Ciphertext length   : %zu bytes\n", kem->length_ciphertext);
    printf("   Shared secret length: %zu bytes\n", kem->length_shared_secret);

    clock_t start = clock();

    // Keypair
    OQS_KEM_keypair(kem, public_key, secret_key);

    // Encapsulate & decapsulate
    OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key);
    OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key);

    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    printf("   ⏱️ KeyGen+Encap+Decap time: %.4f sec\n", elapsed);

    if (memcmp(shared_secret_enc, shared_secret_dec, kem->length_shared_secret) == 0) {
        printf("   ✅ Shared secrets match.\n");
    } else {
        printf("   ❌ Shared secrets mismatch!\n");
    }

    // Encrypt/Decrypt the image with AES
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    unsigned char *enc_buf = malloc(img_len + 32);
    int enc_len = aes_crypt(img_data, img_len, shared_secret_enc, iv, enc_buf, 1);

    unsigned char *dec_buf = malloc(img_len + 32);
    int dec_len = aes_crypt(enc_buf, enc_len, shared_secret_dec, iv, dec_buf, 0);

    // Verify image restored correctly
    if (dec_len == img_len && memcmp(img_data, dec_buf, img_len) == 0) {
        printf("   📷 Image encryption/decryption successful.\n");
    } else {
        printf("   ⚠️ Image decryption mismatch.\n");
    }

    free(public_key); free(secret_key);
    free(ciphertext); free(shared_secret_enc); free(shared_secret_dec);
    free(enc_buf); free(dec_buf);
    OQS_KEM_free(kem);
}

int main() {
    // Load image
    long img_len;
    unsigned char *img_data = load_file(IMAGE_IN, &img_len);
    if (!img_data) { printf("ERROR: Could not read input image.\n"); return -1; }
    printf("📷 Loaded image (%ld bytes)\n", img_len);

    // Compare Kyber variants
    run_kyber_variant(OQS_KEM_alg_kyber_512, img_data, img_len);
    run_kyber_variant(OQS_KEM_alg_kyber_768, img_data, img_len);
    run_kyber_variant(OQS_KEM_alg_kyber_1024, img_data, img_len);

    free(img_data);
    return 0;
}
