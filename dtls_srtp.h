#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"

typedef struct DtlsSrtp {

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_x509_crt cert;
  mbedtls_pk_context pkey;
  mbedtls_ssl_config conf;
  mbedtls_ssl_context ssl;

  int (*udp_send)(void *ctx, const unsigned char *buf, size_t len);
  int (*udp_recv)(void *ctx, unsigned char *buf, size_t len);

} DtlsSrtp;

int dtls_srtp_init(DtlsSrtp *dtls_srtp);

int dtls_srtp_create_cert(DtlsSrtp *dtls_srtp);

void dtls_srtp_handshake(DtlsSrtp *dtls_srtp);




