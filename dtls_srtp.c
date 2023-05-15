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

int dtls_srtp_init(DtlsSrtp *dtls_srtp) {

  mbedtls_entropy_init(&dtls_srtp->entropy);
  mbedtls_ctr_drbg_init(&dtls_srtp->ctr_drbg);
  mbedtls_x509_crt_init(&dtls_srtp->cert);
  mbedtls_pk_init(&dtls_srtp->pkey);
  mbedtls_ssl_config_init(&dtls_srtp->conf);
  mbedtls_ssl_init(&dtls_srtp->ssl);
  
  return 0;
}

int dtls_srtp_create_cert(DtlsSrtp *dtls_srtp) {

  const char *pers = "dtls_srtp";

  mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, mbedtls_entropy_func, &dtls_srtp->entropy, (const unsigned char *) pers, strlen(pers));

  if (mbedtls_pk_setup(&dtls_srtp->pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
    printf("mbedtls_pk_setup failed\n");
    return -1;
  }

  if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(dtls_srtp->pkey), mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg, 2048, 65537) != 0) {
    printf("mbedtls_rsa_gen_key failed\n");
    return -1;
  }

  mbedtls_x509write_cert crt;

  mbedtls_x509write_crt_init(&crt);

  mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

  mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_issuer_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls_srtp");

  mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls_srtp");

  mbedtls_x509write_crt_set_serial(&crt, 1);

  mbedtls_x509write_crt_set_validity(&crt, "20180101000000", "20280101000000");

  mbedtls_x509write_crt_set_basic_constraints(&crt, 0, 0);

  mbedtls_x509write_crt_set_subject_key_identifier(&crt);

  mbedtls_x509write_crt_set_authority_key_identifier(&crt);

  if (mbedtls_x509_crt_parse_der(&dtls_srtp->cert, crt.buf, crt.len) != 0) {
    printf("mbedtls_x509_crt_parse_der failed\n");
    return -1;
  }
  
}

void dtls_srtp_handshake(DtlsSrtp *dtls_srtp) {

  mbedtls_ssl_config_defaults(&dtls_srtp->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);

  mbedtls_ssl_conf_rng(&dtls_srtp->conf, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

  mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &dtls_srtp->cert, NULL);

  mbedtls_ssl_conf_own_cert(&dtls_srtp->conf, &dtls_srtp->cert, &dtls_srtp->pkey);

  mbedtls_ssl_conf_authmode(&dtls_srtp->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

  mbedtls_ssl_conf_min_version(&dtls_srtp->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_max_version(&dtls_srtp->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

  mbedtls_ssl_conf_ciphersuites(&dtls_srtp->conf, mbedtls_ssl_list_ciphersuites());

  mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);

  mbedtls_ssl_set_bio(&dtls_srtp->ssl, dtls_srtp, dtls_srtp->udp_send, dtls_srtp->udp_recv, NULL);

  while (mbedtls_ssl_handshake(&dtls_srtp->ssl) != 0) {

    printf("mbedtls_ssl_handshake failed\n");
  }

}


