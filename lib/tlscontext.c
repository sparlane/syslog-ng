/*
 * Copyright (c) 2002-2011 Balabit
 * Copyright (c) 1998-2011 Balázs Scheidler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 */

#include "tlscontext.h"
#include "str-utils.h"
#include "messages.h"
#include "compat/openssl_support.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifdef ATL_CHANGE
#include <openssl/ocsp.h>
#endif

gboolean
tls_get_x509_digest(X509 *x, GString *hash_string)
{
  gint j;
  unsigned int n;
  unsigned char md[EVP_MAX_MD_SIZE];
  g_assert(hash_string);

  if (!X509_digest(x, EVP_sha1(), md, &n))
    return FALSE;

  g_string_append(hash_string, "SHA1:");
  for (j = 0; j < (int) n; j++)
    g_string_append_printf(hash_string, "%02X%c", md[j], (j + 1 == (int) n) ?'\0' : ':');

  return TRUE;
}

int
tls_session_verify_fingerprint(X509_STORE_CTX *ctx)
{
  SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  TLSSession *self = SSL_get_app_data(ssl);
  GList *current_fingerprint = self->ctx->trusted_fingerpint_list;
  GString *hash;
  gboolean match = FALSE;
  X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

  if (!current_fingerprint)
    {
      return TRUE;
    }

  if (!cert)
    return match;

  hash = g_string_sized_new(EVP_MAX_MD_SIZE * 3);

  if (tls_get_x509_digest(cert, hash))
    {
      do
        {
          if (strcmp((const gchar *)(current_fingerprint->data), hash->str) == 0)
            {
              match = TRUE;
              break;
            }
        }
      while ((current_fingerprint = g_list_next(current_fingerprint)) != NULL);
    }

  g_string_free(hash, TRUE);
  return match;
}

void
tls_x509_format_dn(X509_NAME *name, GString *dn)
{
  BIO *bio;
  gchar *buf;
  long len;

  bio = BIO_new(BIO_s_mem());
  X509_NAME_print_ex(bio, name, 0, ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_CPLUS_SPC |
                     XN_FLAG_DN_REV);
  len = BIO_get_mem_data(bio, &buf);
  g_string_assign_len(dn, buf, len);
  BIO_free(bio);
}

int
tls_session_verify_dn(X509_STORE_CTX *ctx)
{
  SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  TLSSession *self = SSL_get_app_data(ssl);
  gboolean match = FALSE;
  GList *current_dn = self->ctx->trusted_dn_list;
  X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
  GString *dn;

  if (!current_dn || !cert)
    return TRUE;

  dn = g_string_sized_new(128);
  tls_x509_format_dn(X509_get_subject_name(cert), dn);

  do
    {
      if (g_pattern_match_simple((const gchar *) current_dn->data, dn->str))
        {
          match = TRUE;
          break;
        }
    }
  while ((current_dn = g_list_next(current_dn)) != NULL);
  return match;
}

#ifdef ATL_CHANGE
/*
 * Check that the Extended Key Usage field is present in the certificate.
 * It does not check the values in the field, which is handled already by
 * openssl.  This just ensures that the value is present as required.
 */
int
extendedkey_check(X509 *cert)
{
  int extNum;

  STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;

  int num_of_exts = 0;
  if (exts)
    {
      num_of_exts = sk_X509_EXTENSION_num(exts);
    }

  /*
   * Loop over all extensions and look for Extended Key Usage.
   */
  for (extNum = 0; extNum < num_of_exts; extNum++)
  {
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, extNum);
    if (ext != NULL)
      {
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
        if (obj != NULL)
          {
            unsigned int nid = OBJ_obj2nid(obj);
            if (nid == NID_ext_key_usage)
              {
                return 1;
              }
          }
      }
  }

  return 0;
}

/*
 * The following functionality (ocsp_parse_cert_url and ocsp_check)
 * are taken from freeradius server rlm_eap_tls.c
 */

/*
 * This function gets the issuer certificate from a chain in the
 * X509_STORE_CTX.  Used when the issuer is not in our trusterd store
 * and was sent by the peer.
 */
static int
find_issuer_from_chain (X509 **issuer, X509_STORE_CTX *ctx, X509 *cert)
{
  int i;
  STACK_OF (X509) * chain = X509_STORE_CTX_get_chain (ctx);
  if (chain == NULL)
    {
      return 0;
    }

  for (i = 0; i < sk_X509_num (chain); ++i)
    {
      X509 *cand = sk_X509_value (chain, i);
      if ((X509_NAME_cmp (cand->cert_info->subject, cert->cert_info->issuer) == 0))
        {
          *issuer = cand;
          return 1;
        }
    }

  return 0;
}

/*
 * This function extracts the OCSP Responder URL from an existing x509
 * certificate.
 */
static int
ocsp_parse_cert_url(X509 *cert, char **phost, char **pport, char **ppath, int *pssl)
{
  int i;

  AUTHORITY_INFO_ACCESS *aia;
  ACCESS_DESCRIPTION *ad;

  aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++)
    {
      ad = sk_ACCESS_DESCRIPTION_value(aia, i);
      if (OBJ_obj2nid(ad->method) == NID_ad_OCSP)
        {
          if (ad->location->type == GEN_URI)
            {
              if(OCSP_parse_url((char*)ad->location->d.ia5->data,
                                phost, pport, ppath, pssl))
                {
                  return 1;
                }
            }
        }
    }

  return 0;
}

/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD     (5 * 60)

typedef enum
{
  OCSP_NOT_PRESENT,
  OCSP_INVALID,
  OCSP_VALID,
  OCSP_CONNECTION_FAILED,
} OCSPCheckResult;

/*
 * Send an OCSP request to the OCSP responder (if set in the certificate)
 * and validate the OCSP response.
 * Returns:
 * OCSP_NOT_PRESENT - No OCSP in certificate
 * OCSP_INVALID - OCSP response indicates the certificate is not valid
 * OCSP_VALID   - OCSP response says certficate is valid
 * OCSP_CONNECTION_FAILED - Unable to connect to OCSP responder
 *
 */
static OCSPCheckResult
ocsp_check(X509_STORE *store, X509 *issuer_cert, X509 *client_cert)
{
  OCSP_CERTID *certid;
  OCSP_REQUEST *req;
  OCSP_RESPONSE *resp = NULL;
  OCSP_BASICRESP *bresp = NULL;
  char *host = NULL;
  char *port = NULL;
  char *path = NULL;
  int use_ssl = -1;
  long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
  BIO *cbio;
  OCSPCheckResult ocsp_result = OCSP_INVALID;
  int status ;
  ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
  int reason;

  /* Get OCSP responder URL */
  if (!ocsp_parse_cert_url(client_cert, &host, &port, &path, &use_ssl))
    {
      /* No OCSP to check */
      msg_debug("[ocsp] No OCSP URL found in certificate", NULL);
      return OCSP_NOT_PRESENT;
    }

  msg_verbose("[ocsp] ",
              evt_tag_str("Host", host),
              evt_tag_str("Port", port),
              evt_tag_str("Path", path),
              NULL);

  /*
   * Create OCSP Request
   */
  certid = OCSP_cert_to_id(NULL, client_cert, issuer_cert);
  req = OCSP_REQUEST_new();
  OCSP_request_add0_id(req, certid);
  OCSP_request_add1_nonce(req, NULL, 8);

  /*
   * Send OCSP Request and get OCSP Response
   */

  /* Setup BIO socket to OCSP responder */
  cbio = BIO_new_connect(host);

  BIO_set_conn_port(cbio, port);
  BIO_do_connect(cbio);

  /* Send OCSP request and wait for response */
  resp = OCSP_sendreq_bio(cbio, path, req);
  if (resp==0)
    {
      msg_error("[ocsp] Couldn't get OCSP response", NULL);
      ocsp_result = OCSP_CONNECTION_FAILED;
      goto ocsp_end;
    }

  /* Verify OCSP response status */
  status = OCSP_response_status(resp);
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      msg_error("[ocsp] ",
                evt_tag_str("Response status", OCSP_response_status_str(status)), NULL);
      ocsp_result = OCSP_CONNECTION_FAILED;
      goto ocsp_end;
    }
  bresp = OCSP_response_get1_basic(resp);
  if (bresp==0)
    {
      msg_verbose("[ocsp] Couldn't get basic resp", NULL);
      goto ocsp_end;
    }

  if (OCSP_check_nonce(req, bresp)!=1)
    {
      msg_verbose("[ocsp] Response has wrong nonce value", NULL);
      goto ocsp_end;
    }

  if (OCSP_basic_verify(bresp, NULL, store, 0)!=1)
    {
      msg_verbose("[ocsp] Couldn't verify basic response", NULL);
      goto ocsp_end;
    }

  /*  Verify OCSP cert status */
  if (!OCSP_resp_find_status(bresp, certid, &status, &reason, &rev, &thisupd, &nextupd))
    {
      msg_verbose("[ocsp] No Status found.", NULL);
      goto ocsp_end;
    }

  if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage))
    {
      msg_verbose("[ocsp] Status times invalid.", NULL);
      goto ocsp_end;
    }

  if (V_OCSP_CERTSTATUS_GOOD == status)
    {
      msg_debug("[ocsp] Cert status: good", NULL);
      ocsp_result = OCSP_VALID;
    }
  else
    {
      msg_verbose("[ocsp] ", evt_tag_int("Cert status", status), NULL);
    }

ocsp_end:
  /* Free OCSP Stuff */
  OCSP_REQUEST_free(req);
  OCSP_RESPONSE_free(resp);
  free(host);
  free(port);
  free(path);
  BIO_free_all(cbio);
  OCSP_BASICRESP_free(bresp);

  if (1 == ocsp_result)
    {
      msg_verbose("[ocsp] Certificate is valid!", NULL);
    }
  else if (0 == ocsp_result)
    {
      msg_verbose("[ocsp] Certificate has been expired/revoked!", NULL);
    }
  else
    {
     msg_verbose("[ocsp] Unable to verify OCSP", NULL);
    }

  return ocsp_result;
}
#endif

int
tls_session_verify(TLSSession *self, int ok, X509_STORE_CTX *ctx)
{
#ifdef ATL_CHANGE
  X509 *client_cert;
  X509 *issuer_cert;
#endif

  /* untrusted means that we have to accept the certificate even if it is untrusted */
  if (self->ctx->verify_mode & TVM_UNTRUSTED)
    return 1;

  int ctx_error_depth = X509_STORE_CTX_get_error_depth(ctx);
  /* accept certificate if its fingerprint matches, again regardless whether x509 certificate validation was successful */
  if (ok && ctx_error_depth == 0 && !tls_session_verify_fingerprint(ctx))
    {
      msg_notice("Certificate valid, but fingerprint constraints were not met, rejecting");
      return 0;
    }

  X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
  if (ok && ctx_error_depth != 0 && (X509_get_extension_flags(current_cert) & EXFLAG_CA) == 0)
    {
      msg_notice("Invalid certificate found in chain, basicConstraints.ca is unset in non-leaf certificate");
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_INVALID_CA);
      return 0;
    }
 
#ifdef ATL_CHANGE

  /*
   * This section adds 2 checks to the verify.
   *
   * 1) Reject the session if the Extended Key Usage field is not present in
   *    the certificate.  The openssl code already verifies that the data in
   *    the field is valid if present but it does not reject the connection if
   *    the field is not present.  The field is required for Common Criteria.
   *
   * 2) If the certificate contains OCSP data then use that to check if the
   *    certificate has been revoked.  If the OSCP responder cannot be
   *    reached then we still allow the connection.  Only a successful
   *    connection to the OCSP responder that indicates that the certificate
   *    is not valid will cause the connection to not be allowed.
   *
   */

  client_cert = X509_STORE_CTX_get_current_cert(ctx);

  if (ctx->error_depth == 0)
    {
      if (!extendedkey_check(client_cert))
        {
          msg_error("Extended Key Usage check failed", NULL);
          ctx->error = X509_V_ERR_INVALID_PURPOSE;
          return 0;
        }
    }

  if (X509_STORE_CTX_get1_issuer(&issuer_cert, ctx, client_cert)!=1)
    {
      if (find_issuer_from_chain (&issuer_cert, ctx, client_cert) != 1)
        {
          msg_error("Failed to get issuer certificate for verification", NULL);
          ctx->error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
          return 0;
        }
    }
  else
    {
      if (ok && (ocsp_check(ctx->ctx, issuer_cert, client_cert) == OCSP_INVALID))
        {
          msg_error("OCSP check failed", NULL);
          ctx->error = X509_V_ERR_CERT_REVOKED;
          return 0;
        }
    }
#endif

  /* reject certificate if it is valid, but its DN is not trusted */
  if (ok && ctx_error_depth == 0 && !tls_session_verify_dn(ctx))
    {
      msg_notice("Certificate valid, but DN constraints were not met, rejecting");
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_UNTRUSTED);
      return 0;
    }
  /* if the crl_dir is set in the configuration file but the directory is empty ignore this error */
  if (!ok && X509_STORE_CTX_get_error(ctx) == X509_V_ERR_UNABLE_TO_GET_CRL)
    {
      msg_notice("CRL directory is set but no CRLs found");
      return 1;
    }

  if (!ok && X509_STORE_CTX_get_error(ctx) == X509_V_ERR_INVALID_PURPOSE)
    {
      msg_warning("Certificate valid, but purpose is invalid");
      return 1;
    }
  return ok;
}

int
tls_session_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  TLSSession *self = SSL_get_app_data(ssl);
  /* NOTE: Sometimes libssl calls this function
     with no current_cert. This happens when
     some global error is happen. At this situation
     we do not need to call any other check and callback
   */
  if (X509_STORE_CTX_get_current_cert(ctx) == NULL)
    {
      int ctx_error = X509_STORE_CTX_get_error(ctx);
      switch (ctx_error)
        {
        case X509_V_ERR_NO_EXPLICIT_POLICY:
          /* NOTE: Because we set the CHECK_POLICY_FLAG if the
             certificate contains ExplicitPolicy constraint
             we would get this error. But this error is because
             we do not set the policy what we want to check for.
           */
          ok = 1;
          break;
        default:
          msg_notice("Error occured during certificate validation",
                     evt_tag_int("error", X509_STORE_CTX_get_error(ctx)));
          break;
        }
    }
  else
    {
      ok = tls_session_verify(self, ok, ctx);

      tls_log_certificate_validation_progress(ok, ctx);

      if (self->verify_func)
        return self->verify_func(ok, ctx, self->verify_data);
    }
  return ok;
}

void
tls_session_set_trusted_fingerprints(TLSContext *self, GList *fingerprints)
{
  g_assert(fingerprints);

  self->trusted_fingerpint_list = fingerprints;
}

void
tls_session_set_trusted_dn(TLSContext *self, GList *dn)
{
  g_assert(dn);

  self->trusted_dn_list = dn;
}

void
tls_session_set_verify(TLSSession *self, TLSSessionVerifyFunc verify_func, gpointer verify_data,
                       GDestroyNotify verify_destroy)
{
  self->verify_func = verify_func;
  self->verify_data = verify_data;
  self->verify_data_destroy = verify_destroy;
}

void
tls_session_info_callback(const SSL *ssl, int where, int ret)
{
  TLSSession *self = (TLSSession *)SSL_get_app_data(ssl);
  if( !self->peer_info.found && where == (SSL_ST_ACCEPT|SSL_CB_LOOP) )
    {
      X509 *cert = SSL_get_peer_certificate(ssl);

      if(cert)
        {
          self->peer_info.found = 1; /* mark this found so we don't keep checking on every callback */
          X509_NAME *name = X509_get_subject_name(cert);

          X509_NAME_get_text_by_NID( name, NID_commonName, self->peer_info.cn, X509_MAX_CN_LEN );
          X509_NAME_get_text_by_NID( name, NID_organizationName, self->peer_info.o, X509_MAX_O_LEN );
          X509_NAME_get_text_by_NID( name, NID_organizationalUnitName, self->peer_info.ou, X509_MAX_OU_LEN );

          X509_free(cert);
        }
    }
}

static TLSSession *
tls_session_new(SSL *ssl, TLSContext *ctx)
{
  TLSSession *self = g_new0(TLSSession, 1);

  self->ssl = ssl;
  self->ctx = ctx;

  /* to set verify callback */
  tls_session_set_verify(self, NULL, NULL, NULL);

  SSL_set_info_callback(ssl, tls_session_info_callback);

  return self;
}

void
tls_session_free(TLSSession *self)
{
  if (self->verify_data && self->verify_data_destroy)
    self->verify_data_destroy(self->verify_data);
  SSL_free(self->ssl);

  g_free(self);
}

static gboolean
file_exists(const gchar *fname)
{
  if (!fname)
    return FALSE;
  if (access(fname, R_OK) < 0)
    {
      msg_error("Error opening TLS file",
                evt_tag_str("filename", fname),
                evt_tag_errno("error", errno));
      return FALSE;
    }
  return TRUE;
}

TLSSession *
tls_context_setup_session(TLSContext *self)
{
  SSL *ssl;
  TLSSession *session;
  gint ssl_error;
  long ssl_options;

  if (!self->ssl_ctx)
    {
      gint verify_mode = 0;
      gint verify_flags = X509_V_FLAG_POLICY_CHECK;

      if (self->mode == TM_CLIENT)
        self->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
      else
        self->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

      if (!self->ssl_ctx)
        goto error;
      if (file_exists(self->key_file) && !SSL_CTX_use_PrivateKey_file(self->ssl_ctx, self->key_file, SSL_FILETYPE_PEM))
        goto error;

      if (file_exists(self->cert_file) && !SSL_CTX_use_certificate_chain_file(self->ssl_ctx, self->cert_file))
        goto error;
      if (self->key_file && self->cert_file && !SSL_CTX_check_private_key(self->ssl_ctx))
        goto error;

      if (file_exists(self->ca_dir) && !SSL_CTX_load_verify_locations(self->ssl_ctx, NULL, self->ca_dir))
        goto error;

      if (file_exists(self->crl_dir) && !SSL_CTX_load_verify_locations(self->ssl_ctx, NULL, self->crl_dir))
        goto error;

      if (self->crl_dir)
        verify_flags |= X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL;

      X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(self->ssl_ctx), verify_flags);

      switch (self->verify_mode)
        {
        case TVM_NONE:
          verify_mode = SSL_VERIFY_NONE;
          break;
        case TVM_OPTIONAL | TVM_UNTRUSTED:
          verify_mode = SSL_VERIFY_NONE;
          break;
        case TVM_OPTIONAL | TVM_TRUSTED:
          verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
          break;
        case TVM_REQUIRED | TVM_UNTRUSTED:
          verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
          break;
        case TVM_REQUIRED | TVM_TRUSTED:
          verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
          break;
        default:
          g_assert_not_reached();
        }

      SSL_CTX_set_verify(self->ssl_ctx, verify_mode, tls_session_verify_callback);

      if (self->ssl_options != TSO_NONE)
        {
          ssl_options=0;
          if(self->ssl_options & TSO_NOSSLv2)
            ssl_options |= SSL_OP_NO_SSLv2;
          if(self->ssl_options & TSO_NOSSLv3)
            ssl_options |= SSL_OP_NO_SSLv3;
          if(self->ssl_options & TSO_NOTLSv1)
            ssl_options |= SSL_OP_NO_TLSv1;
#ifdef SSL_OP_NO_TLSv1_2
          if(self->ssl_options & TSO_NOTLSv11)
            ssl_options |= SSL_OP_NO_TLSv1_1;
          if(self->ssl_options & TSO_NOTLSv12)
            ssl_options |= SSL_OP_NO_TLSv1_2;
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
          if (self->mode == TM_SERVER)
            ssl_options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
          SSL_CTX_set_options(self->ssl_ctx, ssl_options);
        }
      else
        msg_debug("empty ssl options");
      if (self->cipher_suite)
        {
          if (!SSL_CTX_set_cipher_list(self->ssl_ctx, self->cipher_suite))
            goto error;
        }
    }

  ssl = SSL_new(self->ssl_ctx);

  if (self->mode == TM_CLIENT)
    SSL_set_connect_state(ssl);
  else
    SSL_set_accept_state(ssl);

  session = tls_session_new(ssl, self);
  SSL_set_app_data(ssl, session);
  return session;

error:
  ssl_error = ERR_get_error();
  msg_error("Error setting up TLS session context",
            evt_tag_printf("tls_error", "%s:%s:%s", ERR_lib_error_string(ssl_error), ERR_func_error_string(ssl_error),
                           ERR_reason_error_string(ssl_error)));
  ERR_clear_error();
  if (self->ssl_ctx)
    {
      SSL_CTX_free(self->ssl_ctx);
      self->ssl_ctx = NULL;
    }
  return NULL;
}

TLSContext *
tls_context_new(TLSMode mode)
{
  TLSContext *self = g_new0(TLSContext, 1);

  self->mode = mode;
  self->verify_mode = TVM_REQUIRED | TVM_TRUSTED;
  self->ssl_options = TSO_NOSSLv2;
  return self;
}

void
tls_context_free(TLSContext *self)
{
  SSL_CTX_free(self->ssl_ctx);
  g_list_foreach(self->trusted_fingerpint_list, (GFunc) g_free, NULL);
  g_list_foreach(self->trusted_dn_list, (GFunc) g_free, NULL);
  g_free(self->key_file);
  g_free(self->cert_file);
  g_free(self->ca_dir);
  g_free(self->crl_dir);
  g_free(self->cipher_suite);
  g_free(self);
}

TLSVerifyMode
tls_lookup_verify_mode(const gchar *mode_str)
{
  if (strcasecmp(mode_str, "none") == 0)
    return TVM_NONE;
  else if (strcasecmp(mode_str, "optional-trusted") == 0 || strcasecmp(mode_str, "optional_trusted") == 0)
    return TVM_OPTIONAL | TVM_TRUSTED;
  else if (strcasecmp(mode_str, "optional-untrusted") == 0 || strcasecmp(mode_str, "optional_untrusted") == 0)
    return TVM_OPTIONAL | TVM_UNTRUSTED;
  else if (strcasecmp(mode_str, "required-trusted") == 0 || strcasecmp(mode_str, "required_trusted") == 0)
    return TVM_REQUIRED | TVM_TRUSTED;
  else if (strcasecmp(mode_str, "required-untrusted") == 0 || strcasecmp(mode_str, "required_untrusted") == 0)
    return TVM_REQUIRED | TVM_UNTRUSTED;

  return TVM_REQUIRED | TVM_TRUSTED;
}

gint
tls_lookup_options(GList *options)
{
  gint ret=TSO_NONE;
  GList *l;
  for (l=options; l != NULL; l=l->next)
    {
      msg_debug("ssl-option", evt_tag_str("opt", l->data));
      if (strcasecmp(l->data, "no-sslv2") == 0 || strcasecmp(l->data, "no_sslv2") == 0)
        ret|=TSO_NOSSLv2;
      else if (strcasecmp(l->data, "no-sslv3") == 0 || strcasecmp(l->data, "no_sslv3") == 0)
        ret|=TSO_NOSSLv3;
      else if (strcasecmp(l->data, "no-tlsv1") == 0 || strcasecmp(l->data, "no_tlsv1") == 0)
        ret|=TSO_NOTLSv1;
#ifdef SSL_OP_NO_TLSv1_2
      else if (strcasecmp(l->data, "no-tlsv11") == 0 || strcasecmp(l->data, "no_tlsv11") == 0)
        ret|=TSO_NOTLSv11;
      else if (strcasecmp(l->data, "no-tlsv12") == 0 || strcasecmp(l->data, "no_tlsv12") == 0)
        ret|=TSO_NOTLSv12;
#endif
      else
        msg_error("Unknown ssl-option", evt_tag_str("option", l->data));
    }
  msg_debug("ssl-options parsed", evt_tag_printf("parsed value", "%d", ret));
  return ret;
}

void
tls_log_certificate_validation_progress(int ok, X509_STORE_CTX *ctx)
{
  X509 *xs;
  GString *subject_name, *issuer_name;

  xs = X509_STORE_CTX_get_current_cert(ctx);

  subject_name = g_string_sized_new(128);
  issuer_name = g_string_sized_new(128);
  tls_x509_format_dn(X509_get_subject_name(xs), subject_name);
  tls_x509_format_dn(X509_get_issuer_name(xs), issuer_name);

  if (ok)
    {
      msg_debug("Certificate validation progress",
                evt_tag_str("subject", subject_name->str),
                evt_tag_str("issuer", issuer_name->str));
    }
  else
    {
      gint errnum, errdepth;

      errnum = X509_STORE_CTX_get_error(ctx);
      errdepth = X509_STORE_CTX_get_error_depth(ctx);
      msg_error("Certificate validation failed",
                evt_tag_str("subject", subject_name->str),
                evt_tag_str("issuer", issuer_name->str),
                evt_tag_str("error", X509_verify_cert_error_string(errnum)),
                evt_tag_int("depth", errdepth));
    }
  g_string_free(subject_name, TRUE);
  g_string_free(issuer_name, TRUE);
}

static gboolean
tls_wildcard_match(const gchar *host_name, const gchar *pattern)
{
  gchar **pattern_parts, **hostname_parts;
  gboolean success = FALSE;
  gchar *lower_pattern = NULL;
  gchar *lower_hostname = NULL;
  gint i;

  pattern_parts = g_strsplit(pattern, ".", 0);
  hostname_parts = g_strsplit(host_name, ".", 0);
  for (i = 0; pattern_parts[i]; i++)
    {
      if (!hostname_parts[i])
        {
          /* number of dot separated entries is not the same in the hostname and the pattern spec */
          goto exit;
        }

      lower_pattern = g_ascii_strdown(pattern_parts[i],-1);
      lower_hostname = g_ascii_strdown(hostname_parts[i],-1);

      if (!g_pattern_match_simple(lower_pattern, lower_hostname))
        goto exit;
    }
  success = TRUE;
exit:
  g_free(lower_pattern);
  g_free(lower_hostname);
  g_strfreev(pattern_parts);
  g_strfreev(hostname_parts);
  return success;
}

gboolean
tls_verify_certificate_name(X509 *cert, const gchar *host_name)
{
  gchar pattern_buf[256];
  gint ext_ndx;
  gboolean found = FALSE, result = FALSE;

  ext_ndx = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
  if (ext_ndx >= 0)
    {
      /* ok, there's a subjectAltName extension, check that */
      X509_EXTENSION *ext;
      STACK_OF(GENERAL_NAME) *alt_names;
      GENERAL_NAME *gen_name;

      ext = X509_get_ext(cert, ext_ndx);
      alt_names = X509V3_EXT_d2i(ext);
      if (alt_names)
        {
          gint num, i;

          num = sk_GENERAL_NAME_num(alt_names);

          for (i = 0; !result && i < num; i++)
            {
              gen_name = sk_GENERAL_NAME_value(alt_names, i);
              if (gen_name->type == GEN_DNS)
                {
                  const guchar *dnsname = ASN1_STRING_get0_data(gen_name->d.dNSName);
                  guint dnsname_len = ASN1_STRING_length(gen_name->d.dNSName);

                  if (dnsname_len > sizeof(pattern_buf) - 1)
                    {
                      found = TRUE;
                      result = FALSE;
                      break;
                    }

                  memcpy(pattern_buf, dnsname, dnsname_len);
                  pattern_buf[dnsname_len] = 0;
                  /* we have found a DNS name as alternative subject name */
                  found = TRUE;
                  result = tls_wildcard_match(host_name, pattern_buf);
                }
              else if (gen_name->type == GEN_IPADD)
                {
                  char *dotted_ip = inet_ntoa(*(struct in_addr *) gen_name->d.iPAddress->data);

                  g_strlcpy(pattern_buf, dotted_ip, sizeof(pattern_buf));
                  found = TRUE;
                  result = strcasecmp(host_name, pattern_buf) == 0;
                }
            }
          sk_GENERAL_NAME_free(alt_names);
        }
    }
  if (!found)
    {
      /* hmm. there was no subjectAltName (this is deprecated, but still
       * widely used), look up the Subject, most specific CN */
      X509_NAME *name;

      name = X509_get_subject_name(cert);
      if (X509_NAME_get_text_by_NID(name, NID_commonName, pattern_buf, sizeof(pattern_buf)) != -1)
        {
          result = tls_wildcard_match(host_name, pattern_buf);
        }
    }
  if (!result)
    {
      msg_error("Certificate subject does not match configured hostname",
                evt_tag_str("hostname", host_name),
                evt_tag_str("certificate", pattern_buf));
    }
  else
    {
      msg_verbose("Certificate subject matches configured hostname",
                  evt_tag_str("hostname", host_name),
                  evt_tag_str("certificate", pattern_buf));
    }

  return result;
}

