/**
 * @file
 * @brief Example application showing how EAP server code from hostapd can be
 * used as a library.
 * @author Alexandru Mereacre, Jouni Malinen
 * @copyright SPDX-FileCopyrightText: © 2023 edgesec contributors
 * @copyright SPDX-FileCopyrightText: © 2007, Jouni Malinen <j@w1.fi>
 * @copyright SPDX-License-Identifier: BSD-3-clause
 * @version Adapted from [hostap 2.10 -
 * `eap_example/eap_example_server.c`](https://w1.fi/cgit/hostap/tree/eap_example/eap_example_server.c?h=hostap_2_10)
 */

#include <utils/includes.h>

#include <utils/common.h>

#include <crypto/tls.h>
#include <eap_server/eap.h>
#include <utils/wpabuf.h>

void eap_test_peer_rx(const u8 *data, size_t data_len);

struct eap_server_ctx {
  struct eap_eapol_interface *eap_if;
  struct eap_sm *eap;
  void *tls_ctx;
};

static struct eap_server_ctx eap_ctx;

static int server_get_eap_user(void *ctx, const u8 *identity,
                               size_t identity_len, int phase2,
                               struct eap_user *user) {
  (void)ctx;
  (void)identity;
  (void)identity_len;

  os_memset(user, 0, sizeof(*user));

  printf("==> Server Phase2=%d\n", phase2);

  user->methods[0].vendor = EAP_VENDOR_IETF;
  user->methods[0].method = EAP_TYPE_TLS;
  return 0;
}

static const char *server_get_eap_req_id_text(void *ctx, size_t *len) {
  (void)ctx;
  *len = 0;
  return NULL;
}

static struct eapol_callbacks eap_cb;
static struct eap_config eap_conf;

static int eap_test_server_init_tls(void) {
  struct tls_config tconf;
  struct tls_connection_params tparams;

  os_memset(&tconf, 0, sizeof(tconf));
  eap_ctx.tls_ctx = tls_init(&tconf);
  if (eap_ctx.tls_ctx == NULL)
    return -1;

  // How to generate certs:
  // https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309

  os_memset(&tparams, 0, sizeof(tparams));
  tparams.ca_cert = EAP_TEST_DIR "ca.pem";
  tparams.client_cert = EAP_TEST_DIR "server.pem";
  tparams.private_key = EAP_TEST_DIR "server.key";
  tparams.dh_file = EAP_TEST_DIR "dh.conf";

  if (tls_global_set_params(eap_ctx.tls_ctx, &tparams)) {
    printf("Failed to set TLS parameters\n");
    return -1;
  }

  if (tls_global_set_verify(eap_ctx.tls_ctx, 0, 1)) {
    printf("Failed to set check_crl\n");
    return -1;
  }

  return 0;
}

static int eap_server_register_methods(void) {
  int ret = 0;

  // #ifdef EAP_SERVER_IDENTITY
  if (ret == 0)
    ret = eap_server_identity_register();
  // #endif /* EAP_SERVER_IDENTITY */

  // #ifdef EAP_SERVER_MD5
  if (ret == 0)
    ret = eap_server_md5_register();
  // #endif /* EAP_SERVER_MD5 */

  // #ifdef EAP_SERVER_TLS
  if (ret == 0)
    ret = eap_server_tls_register();
  // #endif /* EAP_SERVER_TLS */

  // #ifdef EAP_SERVER_MSCHAPV2
  if (ret == 0)
    ret = eap_server_mschapv2_register();
  // #endif /* EAP_SERVER_MSCHAPV2 */

  // #ifdef EAP_SERVER_PEAP
  if (ret == 0)
    ret = eap_server_peap_register();
    // #endif /* EAP_SERVER_PEAP */

#ifdef EAP_SERVER_TLV
  if (ret == 0)
    ret = eap_server_tlv_register();
#endif /* EAP_SERVER_TLV */

  // #ifdef EAP_SERVER_GTC
  if (ret == 0)
    ret = eap_server_gtc_register();
  // #endif /* EAP_SERVER_GTC */

  // #ifdef EAP_SERVER_TTLS
  if (ret == 0)
    ret = eap_server_ttls_register();
    // #endif /* EAP_SERVER_TTLS */

#ifdef EAP_SERVER_SIM
  if (ret == 0)
    ret = eap_server_sim_register();
#endif /* EAP_SERVER_SIM */

#ifdef EAP_SERVER_AKA
  if (ret == 0)
    ret = eap_server_aka_register();
#endif /* EAP_SERVER_AKA */

#ifdef EAP_SERVER_AKA_PRIME
  if (ret == 0)
    ret = eap_server_aka_prime_register();
#endif /* EAP_SERVER_AKA_PRIME */

  // #ifdef EAP_SERVER_PAX
  if (ret == 0)
    ret = eap_server_pax_register();
  // #endif /* EAP_SERVER_PAX */

  // #ifdef EAP_SERVER_PSK
  if (ret == 0)
    ret = eap_server_psk_register();
  // #endif /* EAP_SERVER_PSK */

  // #ifdef EAP_SERVER_SAKE
  if (ret == 0)
    ret = eap_server_sake_register();
  // #endif /* EAP_SERVER_SAKE */

  // #ifdef EAP_SERVER_GPSK
  if (ret == 0)
    ret = eap_server_gpsk_register();
    // #endif /* EAP_SERVER_GPSK */

#ifdef EAP_SERVER_VENDOR_TEST
  if (ret == 0)
    ret = eap_server_vendor_test_register();
#endif /* EAP_SERVER_VENDOR_TEST */

#ifdef EAP_SERVER_FAST
  if (ret == 0)
    ret = eap_server_fast_register();
#endif /* EAP_SERVER_FAST */

#ifdef EAP_SERVER_WSC
  if (ret == 0)
    ret = eap_server_wsc_register();
#endif /* EAP_SERVER_WSC */

#ifdef EAP_SERVER_IKEV2
  if (ret == 0)
    ret = eap_server_ikev2_register();
#endif /* EAP_SERVER_IKEV2 */

#ifdef EAP_SERVER_TNC
  if (ret == 0)
    ret = eap_server_tnc_register();
#endif /* EAP_SERVER_TNC */

  return ret;
}

int eap_test_server_init(void) {
  struct eap_session_data eap_sess;

  if (eap_server_register_methods() < 0)
    return -1;

  os_memset(&eap_ctx, 0, sizeof(eap_ctx));

  if (eap_test_server_init_tls() < 0)
    return -1;

  os_memset(&eap_cb, 0, sizeof(eap_cb));
  eap_cb.get_eap_user = server_get_eap_user;
  eap_cb.get_eap_req_id_text = server_get_eap_req_id_text;

  os_memset(&eap_conf, 0, sizeof(eap_conf));
  eap_conf.eap_server = 1;
  eap_conf.ssl_ctx = eap_ctx.tls_ctx;

  eap_conf.max_auth_rounds = 100;
  eap_conf.max_auth_rounds_short = 50;

  os_memset(&eap_sess, 0, sizeof(eap_sess));
  eap_ctx.eap = eap_server_sm_init(&eap_ctx, &eap_cb, &eap_conf, &eap_sess);
  if (eap_ctx.eap == NULL)
    return -1;

  eap_ctx.eap_if = eap_get_interface(eap_ctx.eap);

  /* Enable "port" and request EAP to start authentication. */
  eap_ctx.eap_if->portEnabled = true;
  eap_ctx.eap_if->eapRestart = true;

  return 0;
}

void eap_test_server_deinit(void) {
  eap_server_sm_deinit(eap_ctx.eap);
  eap_server_unregister_methods();
  tls_deinit(eap_ctx.tls_ctx);
}

int eap_test_server_step(void) {
  int res, process = 0;

  res = eap_server_sm_step(eap_ctx.eap);

  if (eap_ctx.eap_if->eapReq) {
    printf("==> Request\n");
    process = 1;
    eap_ctx.eap_if->eapReq = 0;
  }

  if (eap_ctx.eap_if->eapSuccess) {
    printf("==> Success\n");
    process = 1;
    res = 0;
    eap_ctx.eap_if->eapSuccess = 0;

    if (eap_ctx.eap_if->eapKeyAvailable) {
      wpa_hexdump(MSG_DEBUG, "EAP keying material", eap_ctx.eap_if->eapKeyData,
                  eap_ctx.eap_if->eapKeyDataLen);
    }
  }

  if (eap_ctx.eap_if->eapFail) {
    printf("==> Fail\n");
    process = 1;
    eap_ctx.eap_if->eapFail = 0;
  }

  if (process && eap_ctx.eap_if->eapReqData) {
    /* Send EAP request to the peer */
    eap_test_peer_rx(wpabuf_head(eap_ctx.eap_if->eapReqData),
                     wpabuf_len(eap_ctx.eap_if->eapReqData));
  }

  return res;
}

void eap_test_server_rx(const u8 *data, size_t data_len) {
  /* Make received EAP message available to the EAP library */
  wpabuf_free(eap_ctx.eap_if->eapRespData);
  eap_ctx.eap_if->eapRespData = wpabuf_alloc_copy(data, data_len);
  if (eap_ctx.eap_if->eapRespData)
    eap_ctx.eap_if->eapResp = true;
}
