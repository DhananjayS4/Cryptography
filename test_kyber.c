#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main() {
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL, *secret_key = NULL;
    uint8_t *ciphertext = NULL, *shared_secret_enc = NULL, *shared_secret_dec = NULL;

    // ==== Step 1: Kyber setup ====
    kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) { printf("ERROR: OQS_KEM_new failed!\n"); return -1; }

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    ciphertext = malloc(kem->length_ciphertext);
    shared_secret_enc = malloc(kem->length_shared_secret);
    shared_secret_dec = malloc(kem->length_shared_secret);

    // Key generation
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("ERROR: keypair generation failed!\n"); return -1;
    }

    // Encapsulation
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key) != OQS_SUCCESS) {
        printf("ERROR: encapsulation failed!\n"); return -1;
    }

    // Decapsulation
    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key) != OQS_SUCCESS) {
        printf("ERROR: decapsulation failed!\n"); return -1;
    }

    if (memcmp(shared_secret_enc, shared_secret_dec, kem->length_shared_secret) == 0) {
        printf("✅ Kyber: Shared secrets match.\n");
    } else {
        printf("❌ Kyber: Shared secrets do NOT match!\n");
        return -1;
    }

    // ==== Step 2: Load image ====
    long img_len;
    unsigned char *img_data = load_file(IMAGE_IN, &img_len);
    if (!img_data) { printf("ERROR: Could not read input image.\n"); return -1; }
    printf("📷 Loaded image (%ld bytes)\n", img_len);

    // ==== Step 3: Encrypt with AES using shared secret ====
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    unsigned char *enc_buf = malloc(img_len + 32);
    int enc_len = aes_crypt(img_data, img_len, shared_secret_enc, iv, enc_buf, 1);

    // Save ciphertext + IV
    FILE *fenc = fopen(IMAGE_ENC, "wb");
    fwrite(iv, 1, sizeof(iv), fenc);
    fwrite(enc_buf, 1, enc_len, fenc);
    fclose(fenc);
    printf("🔒 Image encrypted -> %s\n", IMAGE_ENC);

    // ==== Step 4: Decrypt ====
    FILE *fdec_in = fopen(IMAGE_ENC, "rb");
    fread(iv, 1, sizeof(iv), fdec_in);
    unsigned char *enc_file_buf = malloc(enc_len);
    fread(enc_file_buf, 1, enc_len, fdec_in);
    fclose(fdec_in);

    unsigned char *dec_buf = malloc(img_len + 32);
    int dec_len = aes_crypt(enc_file_buf, enc_len, shared_secret_dec, iv, dec_buf, 0);

    save_file(IMAGE_DEC, dec_buf, dec_len);
    printf("✅ Image decrypted -> %s\n", IMAGE_DEC);

    // ==== Cleanup ====
    free(public_key); free(secret_key);
    free(ciphertext); free(shared_secret_enc); free(shared_secret_dec);
    free(img_data); free(enc_buf); free(enc_file_buf); free(dec_buf);
    OQS_KEM_free(kem);

    return 0;
}
