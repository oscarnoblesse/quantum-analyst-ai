/*
 * bench_pqc : mesure le coût d'un handshake TLS 1.3 avec un groupe d'échange de clés donné.
 *
 * Usage : bench_pqc <hote> <port> <groupes> <echauffement> <mesures>
 *   bench_pqc 127.0.0.1 8443 X25519MLKEM768 100 1000
 *
 * Pour chaque handshake : une nouvelle connexion TCP, puis SSL_connect mesuré (CLOCK_MONOTONIC).
 * Le temps TCP n'est pas compté : seul le TLS est mesuré.
 * Taille des messages : octets en clair du ClientHello et du ServerHello (le key_share est
 * l'élément qui change avec ML-KEM). Les messages chiffrés de TLS 1.3 ne sont pas comptés.
 *
 * Sortie : une ligne CSV par handshake mesuré, sur la sortie standard.
 * Aucune donnée n'est échangée au-delà du handshake ; le serveur est celui du laboratoire.
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    size_t client_hello;
    size_t server_hello;
    size_t certificat;  /* message Certificate envoyé par le serveur */
} Tailles;

static void msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl;
    Tailles *t = (Tailles *)arg;
    if (content_type != SSL3_RT_HANDSHAKE || len < 4) return;
    const unsigned char *b = buf;
    if (write_p && b[0] == 1) t->client_hello = len;   /* ClientHello */
    if (!write_p && b[0] == 2) t->server_hello = len;  /* ServerHello */
    if (!write_p && b[0] == 11) t->certificat = len;   /* Certificate */
}

static double maintenant_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int connecter_tcp(const char *hote, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in adr = {0};
    adr.sin_family = AF_INET;
    adr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, hote, &adr.sin_addr) != 1 || connect(fd, (struct sockaddr *)&adr, sizeof adr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "Usage : %s <hote> <port> <groupes> <echauffement> <mesures>\n", argv[0]);
        return 2;
    }
    const char *hote = argv[1];
    int port = atoi(argv[2]);
    const char *groupes = argv[3];
    int echauffement = atoi(argv[4]);
    int mesures = atoi(argv[5]);

    if (strcmp(hote, "127.0.0.1") != 0) {
        fprintf(stderr, "Refusé : seul 127.0.0.1 est mesuré (laboratoire local).\n");
        return 2;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return 1; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_set1_groups_list(ctx, groupes) != 1) {
        fprintf(stderr, "Groupe inconnu de cette version d'OpenSSL : %s\n", groupes);
        return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    Tailles tailles = {0, 0, 0};
    SSL_CTX_set_msg_callback(ctx, msg_callback);
    SSL_CTX_set_msg_callback_arg(ctx, &tailles);

    printf("iteration,microsecondes,client_hello,server_hello,certificat,groupe\n");
    for (int i = 0; i < echauffement + mesures; i++) {
        int fd = connecter_tcp(hote, port);
        if (fd < 0) { perror("connect"); return 1; }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        tailles.client_hello = tailles.server_hello = tailles.certificat = 0;

        double debut = maintenant_us();
        int ok = SSL_connect(ssl);
        double fin = maintenant_us();
        if (ok != 1) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl); close(fd); SSL_CTX_free(ctx);
            return 1;
        }

        if (i >= echauffement) {
            printf("%d,%.1f,%zu,%zu,%zu,%s\n", i - echauffement, fin - debut,
                   tailles.client_hello, tailles.server_hello, tailles.certificat, SSL_get0_group_name(ssl));
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }
    SSL_CTX_free(ctx);
    return 0;
}
