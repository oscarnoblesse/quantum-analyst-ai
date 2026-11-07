/*
 * bench_signatures : temps de génération, signature et vérification d'un algorithme de signature
 * post-quantique (ML-DSA ou SLH-DSA) avec l'API EVP d'OpenSSL, plus les tailles.
 *
 * Usage : bench_signatures <algorithme> <echauffement> <mesures>
 *   bench_signatures ML-DSA-65 10 200
 *
 * Sortie CSV sur la sortie standard : une ligne par itération mesurée, en microsecondes,
 * puis les tailles (clé publique, signature) lues sur la première itération.
 * Les opérations sont faites par OpenSSL, jamais par le modèle de langage.
 */

#define _POSIX_C_SOURCE 200809L

#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double maintenant_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static EVP_PKEY *generer(const char *algo) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
    EVP_PKEY *cle = NULL;
    if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &cle) != 1) cle = NULL;
    EVP_PKEY_CTX_free(ctx);
    return cle;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage : %s <algorithme> <echauffement> <mesures>\n", argv[0]);
        return 2;
    }
    const char *algo = argv[1];
    int echauffement = atoi(argv[2]);
    int mesures = atoi(argv[3]);
    /* Message fixe : la signature porte sur 64 octets, comme un condensat de transcription. */
    unsigned char message[64];
    memset(message, 0x5a, sizeof message);

    printf("iteration,generation_us,signature_us,verification_us\n");
    size_t taille_cle = 0, taille_sig = 0;
    for (int i = 0; i < echauffement + mesures; i++) {
        double t0 = maintenant_us();
        EVP_PKEY *cle = generer(algo);
        double t1 = maintenant_us();
        if (!cle) { fprintf(stderr, "Algorithme inconnu ou génération impossible : %s\n", algo); ERR_print_errors_fp(stderr); return 1; }

        EVP_MD_CTX *signe = EVP_MD_CTX_new();
        size_t n_sig = 0;
        unsigned char *sig = NULL;
        double t2 = 0, t3 = 0;
        if (EVP_DigestSignInit_ex(signe, NULL, NULL, NULL, NULL, cle, NULL) != 1) { ERR_print_errors_fp(stderr); return 1; }
        /* Première passe pour connaître la taille de la signature. */
        if (EVP_DigestSign(signe, NULL, &n_sig, message, sizeof message) != 1) { ERR_print_errors_fp(stderr); return 1; }
        sig = malloc(n_sig);
        t2 = maintenant_us();
        if (EVP_DigestSign(signe, sig, &n_sig, message, sizeof message) != 1) { ERR_print_errors_fp(stderr); return 1; }
        t3 = maintenant_us();
        EVP_MD_CTX_free(signe);
        double t4 = 0, t5 = 0;

        unsigned char *pub = NULL;
        size_t n_pub = 0;
        EVP_PKEY_get_raw_public_key(cle, NULL, &n_pub);
        pub = malloc(n_pub);
        EVP_PKEY_get_raw_public_key(cle, pub, &n_pub);

        EVP_MD_CTX *verifie = EVP_MD_CTX_new();
        t4 = maintenant_us();
        int ok = EVP_DigestVerifyInit_ex(verifie, NULL, NULL, NULL, NULL, cle, NULL) == 1
              && EVP_DigestVerify(verifie, sig, n_sig, message, sizeof message) == 1;
        t5 = maintenant_us();
        EVP_MD_CTX_free(verifie);
        if (!ok) { fprintf(stderr, "Vérification échouée : bug dans l'outil\n"); return 1; }

        if (i == 0) { taille_cle = n_pub; taille_sig = n_sig; }
        if (i >= echauffement) {
            printf("%d,%.1f,%.1f,%.1f\n", i - echauffement, t1 - t0, t3 - t2, t5 - t4);
        }
        free(sig);
        free(pub);
        EVP_PKEY_free(cle);
    }
    printf("# algorithme=%s cle_publique_octets=%zu signature_octets=%zu\n", algo, taille_cle, taille_sig);
    return 0;
}
