/*
 * gen_pq_chain_wolfssl.c  --  X9.146 dual-alg cert chain generator
 *
 * Generates a 3-level cert chain where every cert carries BOTH:
 *   Primary signature : ML-DSA-44       (standard X.509 signatureAlgorithm /
 *                                        signatureValue fields)
 *   Alternative sig   : ECDSA-P-256 + SHA-256  (X9.146 extensions:
 *                                        subjectAltPublicKeyInfo  2.5.29.72
 *                                        altSignatureAlgorithm    2.5.29.73
 *                                        altSignatureValue        2.5.29.74)
 *
 *   Root CA (ML-DSA-44 self + ECC self)
 *       |
 *       +-- Intermediate CA (ML-DSA-44 signed by root-pq, ECC signed by root-ecc)
 *               |
 *               +-- Leaf CN=192.168.0.100 (signed likewise by the intermediate)
 *
 * Emits:
 *   out/root_cert.pem  int_cert.pem  leaf_cert.pem
 *   out/chain_cert.pem                        (leaf + intermediate PEM)
 *   out/leaf_key.der                          (PKCS#8 primary ML-DSA-44 key)
 *   out/certs_pqc.h                           (chain_cert_pem[] / leaf_key_der[])
 *
 * At handshake time the STM32 server still signs CertificateVerify with
 * ML-DSA-44 only.  The alt sigs live entirely inside the chain.  Peers
 * that understand X9.146 (wolfSSL built --enable-dual-alg-certs) verify
 * BOTH chains; peers that don't, treat the three extensions as unknown
 * non-critical and accept the chain on the primary sigs alone.
 *
 * Build:  tools/build_wolfssl_gen.sh
 *         requires  ./configure --enable-dual-alg-certs --enable-ecc \
 *                               --enable-dilithium --enable-tls13   \
 *                               --enable-certgen --enable-certreq   \
 *                               --enable-certext --enable-experimental
 */

#include <wolfssl/options.h>
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef WOLFSSL_DUAL_ALG_CERTS
# error "MSYS2 wolfSSL is missing X9.146 support.  Rebuild with:\n" \
        "  ./configure --enable-dual-alg-certs --enable-ecc \\\n"  \
        "              --enable-dilithium --enable-tls13 \\\n"     \
        "              --enable-certgen --enable-certreq --enable-certext \\\n" \
        "              --enable-experimental --enable-static --disable-shared\n" \
        "  make -j$(nproc)"
#endif

#define CHECK(expr, msg) do { \
    int _r = (expr); \
    if (_r < 0) { \
        fprintf(stderr, "ERR: %s: %d (%s)\n", (msg), _r, \
                wc_GetErrorString(_r)); \
        exit(1); \
    } \
} while (0)

#define BUF_SZ  32768

/* ------------------------------------------------------------------ */
/* PQ_LEVEL selects the ML-DSA parameter set at compile time:           */
/*   2 -> ML-DSA-44  (NIST L2, 1312 B pubkey, 2420 B sig)              */
/*   3 -> ML-DSA-65  (NIST L3, 1952 B pubkey, 3309 B sig)              */
/*   5 -> ML-DSA-87  (NIST L5, 2592 B pubkey, 4627 B sig)              */
/* Default is 2 (matches the N=1000 paper baseline).  Override with    */
/*   gcc ... -DPQ_LEVEL=3 ...                                          */
/* ------------------------------------------------------------------ */
#ifndef PQ_LEVEL
# define PQ_LEVEL 2
#endif
#if PQ_LEVEL == 2
# define PQ_WC_LEVEL   WC_ML_DSA_44
# define PQ_CTC_SIG    CTC_ML_DSA_LEVEL2
# define PQ_KEY_TYPE   ML_DSA_LEVEL2_TYPE
# define PQ_NAME       "ML-DSA-44"
#elif PQ_LEVEL == 3
# define PQ_WC_LEVEL   WC_ML_DSA_65
# define PQ_CTC_SIG    CTC_ML_DSA_LEVEL3
# define PQ_KEY_TYPE   ML_DSA_LEVEL3_TYPE
# define PQ_NAME       "ML-DSA-65"
#elif PQ_LEVEL == 5
# define PQ_WC_LEVEL   WC_ML_DSA_87
# define PQ_CTC_SIG    CTC_ML_DSA_LEVEL5
# define PQ_KEY_TYPE   ML_DSA_LEVEL5_TYPE
# define PQ_NAME       "ML-DSA-87"
#else
# error "PQ_LEVEL must be 2, 3 or 5"
#endif

/* ------------------------------------------------------------------ */
/* DER-encoded AlgorithmIdentifier for ecdsa-with-SHA256               */
/*   SEQUENCE { OID 1.2.840.10045.4.3.2 } , no parameters              */
/*   30 0A 06 08 2A 86 48 CE 3D 04 03 02                              */
/* ------------------------------------------------------------------ */
static const unsigned char ecdsa_sha256_algid[] = {
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void write_file(const char *path, const unsigned char *buf, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    if (fwrite(buf, 1, n, f) != n) { perror("fwrite"); exit(1); }
    fclose(f);
    printf("  wrote %s (%zu B)\n", path, n);
}

static int make_ml_dsa_44(dilithium_key *key, WC_RNG *rng)
{
    int ret;
    ret = wc_dilithium_init(key);                    if (ret) return ret;
    ret = wc_dilithium_set_level(key, PQ_WC_LEVEL);  if (ret) return ret;
    ret = wc_dilithium_make_key(key, rng);           if (ret) return ret;
    return 0;
}

static int make_ecc_p256(ecc_key *key, WC_RNG *rng)
{
    int ret;
    ret = wc_ecc_init(key);                                        if (ret) return ret;
    ret = wc_ecc_make_key_ex(rng, 32, key, ECC_SECP256R1);         if (ret) return ret;
    return 0;
}

static void fill_subject(Cert *cert, const char *cn)
{
    strncpy(cert->subject.country,    "GB",          CTC_NAME_SIZE - 1);
    strncpy(cert->subject.org,        "TLS_X9 Demo", CTC_NAME_SIZE - 1);
    strncpy(cert->subject.commonName, cn,            CTC_NAME_SIZE - 1);
}

static int der_to_pem(const unsigned char *der, int der_sz,
                      unsigned char *pem, int pem_sz, int type)
{
    int r = wc_DerToPem(der, der_sz, pem, pem_sz, type);
    if (r < 0) {
        fprintf(stderr, "wc_DerToPem: %d (%s)\n", r, wc_GetErrorString(r));
        exit(1);
    }
    return r;
}

static void emit_c_array(FILE *f, const char *name,
                         const unsigned char *data, size_t n)
{
    fprintf(f, "unsigned char %s[] = {\n  ", name);
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "0x%02x", data[i]);
        if (i + 1 < n) fputc(',', f);
        if ((i & 15) == 15) fputs("\n  ", f);
        else fputc(' ', f);
    }
    fprintf(f, "\n};\nunsigned int %s_len = %zu;\n\n", name, n);
}

/* ------------------------------------------------------------------ */
/* Build an X9.146 dual-alg signed cert.                               */
/*                                                                     */
/*   subj_pq, subj_ecc  : subject's primary + alt keypairs (pubs go    */
/*                         into the cert)                              */
/*   iss_pq,  iss_ecc   : issuer's primary + alt keypairs              */
/*                         (NULL and self-sign if iss_der==NULL, using */
/*                         subj keys)                                  */
/*   iss_der            : DER cert of issuer (NULL for self-signed)    */
/*                                                                     */
/*   Flow (per RFC X9.146 / draft-ietf-lamps-pq-composite style):      */
/*     (a) encode TBS WITHOUT altSignatureValue   = pre-TBS            */
/*     (b) sign pre-TBS with iss_ecc + SHA-256    = altSignatureValue  */
/*     (c) re-encode TBS WITH altSignatureValue   = final TBS          */
/*     (d) sign final TBS with iss_pq             = primary sig        */
/*                                                                     */
/*   This matches wolfSSL's verifier, which strips altSignatureValue   */
/*   via wc_GeneratePreTBS() and verifies the alt sig over that.       */
/* ------------------------------------------------------------------ */
static int build_dual_cert(Cert           *cert,
                           dilithium_key  *subj_pq,  ecc_key *subj_ecc,
                           dilithium_key  *iss_pq,   ecc_key *iss_ecc,
                           const unsigned char *iss_der, int iss_der_sz,
                           WC_RNG         *rng,
                           unsigned char  *out, int out_sz)
{
    unsigned char subj_ecc_spki[256];   /* P-256 SubjectPublicKeyInfo ~91 B */
    int           spki_sz;
    unsigned char alt_sig_bitstr[160];  /* BIT STRING + ECDSA-P256 sig      */
    int           alt_sig_sz;
    unsigned char pretbs[BUF_SZ];
    int           pretbs_sz;
    unsigned char body[BUF_SZ];
    int           body_sz, signed_sz;
    unsigned char serial[16];
    DecodedCert   dc;
    unsigned char pass1[BUF_SZ];
    int           pass1_body_sz, pass1_sz;

    cert->sigType   = PQ_CTC_SIG;
    cert->daysValid = 3650;
    cert->version   = 2;                 /* v3 */
    cert->keyType   = PQ_KEY_TYPE;

    if (iss_der) {
        CHECK(wc_SetIssuerBuffer(cert, iss_der, iss_der_sz),
              "wc_SetIssuerBuffer");
    } else {
        cert->selfSigned = 1;
    }

    /* Fix the serial up-front so both encoding passes produce identical
     * TBS bytes modulo the altSignatureValue extension.  Without this
     * wc_MakeCert_ex might re-randomize the serial on the second call
     * and invalidate the alt signature we just computed. */
    CHECK(wc_RNG_GenerateBlock(rng, serial, sizeof serial), "RNG serial");
    serial[0] &= 0x7f;                  /* positive integer */
    memcpy(cert->serial, serial, sizeof serial);
    cert->serialSz = sizeof serial;

    /* PIN VALIDITY DATES.  wc_MakeCert() computes notBefore from time(NULL)
     * and notAfter from now + daysValid*86400 each time it runs, unless
     * cert->beforeDateSz / afterDateSz are already non-zero.  Two calls
     * that straddle a second-boundary produce two different TBS byte
     * sequences, which breaks the alt-signature verification because the
     * verifier reconstructs pre-TBS from the final (2nd-call) encoding.
     * Pre-populate the date fields so both passes are byte-identical. */
    {
        time_t    now   = time(NULL);
        time_t    later = now + (time_t)cert->daysValid * 86400L;
        struct tm tm_b, tm_a;
    #ifdef _WIN32
        gmtime_s(&tm_b, &now);
        gmtime_s(&tm_a, &later);
    #else
        struct tm *pb = gmtime(&now);   tm_b = *pb;
        struct tm *pa = gmtime(&later); tm_a = *pa;
    #endif
        /* X.509 rule: UTCTime for years 1950-2049, GeneralizedTime thereafter.
         * daysValid=3650 ~= 10y so we fit UTCTime unless "now" is already
         * past 2039.  Format: YYMMDDHHMMSSZ (13 chars). */
        cert->beforeDate[0] = ASN_UTC_TIME;
        cert->beforeDate[1] = 13;
        strftime((char*)&cert->beforeDate[2], CTC_DATE_SIZE - 2,
                 "%y%m%d%H%M%SZ", &tm_b);
        cert->beforeDateSz = 15;

        cert->afterDate[0] = ASN_UTC_TIME;
        cert->afterDate[1] = 13;
        strftime((char*)&cert->afterDate[2], CTC_DATE_SIZE - 2,
                 "%y%m%d%H%M%SZ", &tm_a);
        cert->afterDateSz = 15;
    }

    /* (1) Serialize the subject's alt ECC pubkey as SubjectPublicKeyInfo. */
    spki_sz = wc_EccPublicKeyToDer(subj_ecc, subj_ecc_spki,
                                   sizeof subj_ecc_spki, 1 /* withAlgCurve */);
    if (spki_sz < 0) {
        fprintf(stderr, "wc_EccPublicKeyToDer: %d (%s)\n",
                spki_sz, wc_GetErrorString(spki_sz));
        exit(1);
    }

    /* (2) Populate X9.146 extension fields for the pre-TBS pass.
     *     Non-critical so non-X9.146-aware peers still accept the cert. */
    cert->sapkiDer      = subj_ecc_spki;
    cert->sapkiLen      = spki_sz;
    cert->sapkiCrit     = 0;
    cert->altSigAlgDer  = (byte *)ecdsa_sha256_algid;
    cert->altSigAlgLen  = sizeof ecdsa_sha256_algid;
    cert->altSigAlgCrit = 0;
    cert->altSigValDer  = NULL;          /* withheld for pre-TBS */
    cert->altSigValLen  = 0;
    cert->altSigValCrit = 0;

    /* (3) PASS 1: produce a fully-signed temporary cert with altSigVal
     *     absent.  The primary signature here is thrown away; we only
     *     need a parseable cert whose fields (subject/issuer/dates/
     *     serial/pubkey/sapki/altSigAlg/extensions) match the final
     *     cert we'll emit in pass 2.  wc_ParseCert + wc_GeneratePreTBS
     *     then givethe exact byte sequence the verifier will
     *     reconstruct from the final cert, because wc_GeneratePreTBS
     *     strips altSigVal and sigOID regardless of what was in the
     *     input.  Signing that guarantees alt-sig verification. */
    pass1_body_sz = wc_MakeCert_ex(cert, pass1, sizeof pass1,
                                   PQ_KEY_TYPE, subj_pq, rng);
    if (pass1_body_sz < 0) {
        fprintf(stderr, "wc_MakeCert_ex (pass1): %d (%s)\n",
                pass1_body_sz, wc_GetErrorString(pass1_body_sz));
        exit(1);
    }
    pass1_sz = wc_SignCert_ex(pass1_body_sz, PQ_CTC_SIG,
                              pass1, sizeof pass1,
                              PQ_KEY_TYPE, iss_pq, rng);
    if (pass1_sz < 0) {
        fprintf(stderr, "wc_SignCert_ex (pass1): %d (%s)\n",
                pass1_sz, wc_GetErrorString(pass1_sz));
        exit(1);
    }

    /* (3b) Parse pass-1 cert and ask wolfSSL for the canonical pre-TBS. */
    wc_InitDecodedCert(&dc, pass1, (word32)pass1_sz, NULL);
    {
        int pret = wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
        if (pret != 0) {
            fprintf(stderr, "wc_ParseCert (pass1): %d (%s)\n",
                    pret, wc_GetErrorString(pret));
            wc_FreeDecodedCert(&dc);
            exit(1);
        }
    }
    pretbs_sz = wc_GeneratePreTBS(&dc, pretbs, sizeof pretbs);
    wc_FreeDecodedCert(&dc);
    if (pretbs_sz <= 0) {
        fprintf(stderr, "wc_GeneratePreTBS: %d (%s)\n",
                pretbs_sz, wc_GetErrorString(pretbs_sz));
        exit(1);
    }

    /* (4) Sign canonical pre-TBS with issuer's alt ECC key, SHA-256 + ECDSA.
     *     wc_MakeSigWithBitStr returns BIT STRING wrapper + sig bytes,
     *     i.e. literally what goes into the altSignatureValue ext. */
    alt_sig_sz = wc_MakeSigWithBitStr(alt_sig_bitstr, sizeof alt_sig_bitstr,
                                      CTC_SHA256wECDSA,
                                      pretbs, (word32)pretbs_sz,
                                      ECC_TYPE, iss_ecc, rng);
    if (alt_sig_sz < 0) {
        fprintf(stderr, "wc_MakeSigWithBitStr: %d (%s)\n",
                alt_sig_sz, wc_GetErrorString(alt_sig_sz));
        exit(1);
    }

    /* (5) PASS 2: plug alt sig in, re-encode TBS with all three X9.146
     *     extensions present.  Since pass-1 and pass-2 share identical
     *     subject/issuer/dates/serial/pubkey/sapki/altSigAlg/extensions,
     *     wc_GeneratePreTBS run on this final cert yields the same
     *     bytes we just signed. */
    cert->altSigValDer = alt_sig_bitstr;
    cert->altSigValLen = alt_sig_sz;

    body_sz = wc_MakeCert_ex(cert, body, sizeof body,
                             PQ_KEY_TYPE, subj_pq, rng);
    if (body_sz < 0) {
        fprintf(stderr, "wc_MakeCert_ex (final TBS): %d (%s)\n",
                body_sz, wc_GetErrorString(body_sz));
        exit(1);
    }

    /* (6) Sign the final TBS with issuer's primary ML-DSA-44 key. */
    signed_sz = wc_SignCert_ex(body_sz, PQ_CTC_SIG,
                               body, sizeof body,
                               PQ_KEY_TYPE, iss_pq, rng);
    if (signed_sz < 0) {
        fprintf(stderr, "wc_SignCert_ex: %d (%s)\n",
                signed_sz, wc_GetErrorString(signed_sz));
        exit(1);
    }
    if (signed_sz > out_sz) {
        fprintf(stderr, "signed cert too large: %d\n", signed_sz);
        exit(1);
    }

    /* (7) SELF-DIAGNOSTIC.  Parse the final cert we just produced, run
     *     wc_GeneratePreTBS on it, and compare that byte sequence
     *     against the bytes we signed above.  If they differ, the
     *     alt-sig we embedded will NEVER verify -- abort so we don't
     *     ship a broken chain. */
    {
        DecodedCert dc2;
        unsigned char pretbs2[BUF_SZ];
        int pretbs2_sz;
        unsigned char h1[32], h2[32];
        wc_Sha256 s;

        wc_InitDecodedCert(&dc2, body, (word32)signed_sz, NULL);
        if (wc_ParseCert(&dc2, CERT_TYPE, NO_VERIFY, NULL) != 0) {
            fprintf(stderr, "SELFCHECK parse fail\n");
            wc_FreeDecodedCert(&dc2);
            exit(1);
        }
        pretbs2_sz = wc_GeneratePreTBS(&dc2, pretbs2, sizeof pretbs2);
        wc_FreeDecodedCert(&dc2);
        if (pretbs2_sz <= 0) {
            fprintf(stderr, "SELFCHECK preTBS2 %d\n", pretbs2_sz);
            exit(1);
        }
        wc_InitSha256(&s);
        wc_Sha256Update(&s, pretbs, (word32)pretbs_sz);
        wc_Sha256Final(&s, h1);
        wc_InitSha256(&s);
        wc_Sha256Update(&s, pretbs2, (word32)pretbs2_sz);
        wc_Sha256Final(&s, h2);
        printf("  preTBS(signed) sz=%d  sha256=%02x%02x%02x%02x...\n",
               pretbs_sz, h1[0], h1[1], h1[2], h1[3]);
        printf("  preTBS(final ) sz=%d  sha256=%02x%02x%02x%02x...\n",
               pretbs2_sz, h2[0], h2[1], h2[2], h2[3]);
        if (pretbs_sz != pretbs2_sz || memcmp(h1, h2, 32) != 0) {
            int i, first = -1;
            int n = pretbs_sz < pretbs2_sz ? pretbs_sz : pretbs2_sz;
            for (i = 0; i < n; i++) {
                if (pretbs[i] != pretbs2[i]) { first = i; break; }
            }
            fprintf(stderr, "SELFCHECK preTBS MISMATCH: "
                    "signed=%d final=%d first_diff=%d\n",
                    pretbs_sz, pretbs2_sz, first);
            if (first >= 0) {
                int lo = first > 16 ? first - 16 : 0;
                int hi = first + 16 < n ? first + 16 : n;
                fprintf(stderr, "  signed[%d..%d]:", lo, hi);
                for (i = lo; i < hi; i++) fprintf(stderr, " %02x", pretbs[i]);
                fprintf(stderr, "\n  final [%d..%d]:", lo, hi);
                for (i = lo; i < hi; i++) fprintf(stderr, " %02x", pretbs2[i]);
                fprintf(stderr, "\n");
            }
            exit(1);
        }
        printf("  SELFCHECK preTBS match: alt-sig will verify.\n");
    }

    memcpy(out, body, signed_sz);
    return signed_sz;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    WC_RNG        rng;
    dilithium_key root_pq, int_pq, leaf_pq;
    ecc_key       root_ecc, int_ecc, leaf_ecc;

    unsigned char root_der[BUF_SZ], int_der[BUF_SZ], leaf_der[BUF_SZ];
    int           root_der_sz,      int_der_sz,      leaf_der_sz;

    unsigned char root_pem[BUF_SZ], int_pem[BUF_SZ], leaf_pem[BUF_SZ];
    int           root_pem_sz,      int_pem_sz,      leaf_pem_sz;

    unsigned char leaf_key_der[BUF_SZ];
    int           leaf_key_der_sz;

    Cert root_cert, int_cert, leaf_cert;

    printf("wolfSSL %s -- X9.146 dual-alg chain generator\n",
           LIBWOLFSSL_VERSION_STRING);
    printf("  primary = ML-DSA-44   alt = ECDSA-P256/SHA-256\n");

    CHECK(wolfCrypt_Init(), "wolfCrypt_Init");
    CHECK(wc_InitRng(&rng), "wc_InitRng");

    /* ----- (1) Six keypairs -------------------------------------- */
    printf("[*] Generating primary ML-DSA-44 keys (x3)...\n");
    CHECK(make_ml_dsa_44(&root_pq, &rng), "make_ml_dsa_44 root");
    CHECK(make_ml_dsa_44(&int_pq,  &rng), "make_ml_dsa_44 int");
    CHECK(make_ml_dsa_44(&leaf_pq, &rng), "make_ml_dsa_44 leaf");
    printf("[*] Generating alternative ECC P-256 keys (x3)...\n");
    CHECK(make_ecc_p256(&root_ecc, &rng), "make_ecc_p256 root");
    CHECK(make_ecc_p256(&int_ecc,  &rng), "make_ecc_p256 int");
    CHECK(make_ecc_p256(&leaf_ecc, &rng), "make_ecc_p256 leaf");

    /* ----- (2) Root CA -- self-signed on BOTH chains ------------- */
    printf("[*] Building Root CA (self-signed, dual)...\n");
    wc_InitCert(&root_cert);
    fill_subject(&root_cert, "PQ Root CA (X9.146)");
    root_cert.isCA          = 1;
    root_cert.basicConstSet = 1;
    root_cert.pathLen       = 1;
    root_cert.pathLenSet    = 1;
    root_cert.keyUsage      = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
    root_der_sz = build_dual_cert(&root_cert,
                                  &root_pq, &root_ecc,
                                  &root_pq, &root_ecc,
                                  NULL, 0, &rng,
                                  root_der, sizeof root_der);

    /* ----- (3) Intermediate CA, signed by Root on both chains ---- */
    printf("[*] Building Intermediate CA (dual)...\n");
    wc_InitCert(&int_cert);
    fill_subject(&int_cert, "PQ Intermediate CA (X9.146)");
    int_cert.isCA           = 1;
    int_cert.basicConstSet  = 1;
    int_cert.pathLen        = 0;
    int_cert.pathLenSet     = 1;
    int_cert.keyUsage       = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
    int_der_sz = build_dual_cert(&int_cert,
                                 &int_pq,  &int_ecc,
                                 &root_pq, &root_ecc,
                                 root_der, root_der_sz, &rng,
                                 int_der, sizeof int_der);

    /* ----- (4) Leaf, signed by Intermediate on both chains ------- */
    printf("[*] Building Leaf CN=192.168.0.100 (dual)...\n");
    wc_InitCert(&leaf_cert);
    fill_subject(&leaf_cert, "192.168.0.100");
    leaf_cert.isCA          = 0;
    leaf_cert.basicConstSet = 1;
    leaf_cert.keyUsage      = KEYUSE_DIGITAL_SIG | KEYUSE_KEY_ENCIPHER;
    leaf_der_sz = build_dual_cert(&leaf_cert,
                                  &leaf_pq, &leaf_ecc,
                                  &int_pq,  &int_ecc,
                                  int_der, int_der_sz, &rng,
                                  leaf_der, sizeof leaf_der);

    /* ----- (4b) CHAIN SELF-VERIFY ---------------------------------
     * Build a CertManager, load root as trust anchor, then try to
     * verify int (signed by root) and leaf (signed by int).  This is
     * exactly what the client does, minus TLS framing.  If THIS fails,
     * the chain is broken locally and no amount of flashing will help.
     */
    {
        WOLFSSL_CERT_MANAGER *cm = wolfSSL_CertManagerNew();
        int r;
        if (!cm) { fprintf(stderr, "CertManagerNew failed\n"); exit(1); }

        r = wolfSSL_CertManagerLoadCABuffer(cm, root_der, root_der_sz,
                                            WOLFSSL_FILETYPE_ASN1);
        if (r != WOLFSSL_SUCCESS) {
            fprintf(stderr, "load root as CA: %d\n", r); exit(1);
        }
        r = wolfSSL_CertManagerVerifyBuffer(cm, int_der, int_der_sz,
                                            WOLFSSL_FILETYPE_ASN1);
        fprintf(stderr, "chain verify int  : %d %s\n", r,
                r == WOLFSSL_SUCCESS ? "OK" : wc_GetErrorString(r));
        if (r != WOLFSSL_SUCCESS) exit(1);

        r = wolfSSL_CertManagerLoadCABuffer(cm, int_der, int_der_sz,
                                            WOLFSSL_FILETYPE_ASN1);
        if (r != WOLFSSL_SUCCESS) {
            fprintf(stderr, "load int as CA: %d\n", r); exit(1);
        }
        r = wolfSSL_CertManagerVerifyBuffer(cm, leaf_der, leaf_der_sz,
                                            WOLFSSL_FILETYPE_ASN1);
        fprintf(stderr, "chain verify leaf : %d %s\n", r,
                r == WOLFSSL_SUCCESS ? "OK" : wc_GetErrorString(r));
        if (r != WOLFSSL_SUCCESS) exit(1);
        wolfSSL_CertManagerFree(cm);
        printf("[*] Full chain verify OK (primary + alt sigs).\n");
    }

    /* ----- (5) PEMify -------------------------------------------- */
    root_pem_sz = der_to_pem(root_der, root_der_sz,
                             root_pem, sizeof root_pem, CERT_TYPE);
    int_pem_sz  = der_to_pem(int_der,  int_der_sz,
                             int_pem,  sizeof int_pem,  CERT_TYPE);
    leaf_pem_sz = der_to_pem(leaf_der, leaf_der_sz,
                             leaf_pem, sizeof leaf_pem, CERT_TYPE);

    /* ----- (6) Leaf primary private key as PKCS#8 DER ------------ */
    leaf_key_der_sz = wc_Dilithium_PrivateKeyToDer(&leaf_pq,
                                                   leaf_key_der,
                                                   sizeof leaf_key_der);
    if (leaf_key_der_sz < 0) {
        fprintf(stderr, "wc_Dilithium_PrivateKeyToDer: %d (%s)\n",
                leaf_key_der_sz, wc_GetErrorString(leaf_key_der_sz));
        exit(1);
    }
    printf("[*] leaf PKCS#8 ML-DSA-44 private key: %d B\n", leaf_key_der_sz);

    /* ----- (7) Write artifacts ----------------------------------- */
#ifdef _WIN32
    system("mkdir out 2>nul");
#else
    system("mkdir -p out");
#endif
    write_file("out/root_cert.pem", root_pem, root_pem_sz);
    write_file("out/int_cert.pem",  int_pem,  int_pem_sz);
    write_file("out/leaf_cert.pem", leaf_pem, leaf_pem_sz);
    write_file("out/leaf_key.der",  leaf_key_der, leaf_key_der_sz);

    /* Chain PEM: leaf || intermediate (server flight order) */
    {
        unsigned char chain[BUF_SZ * 2];
        size_t chain_sz = 0;
        memcpy(chain + chain_sz, leaf_pem, leaf_pem_sz); chain_sz += leaf_pem_sz;
        memcpy(chain + chain_sz, int_pem,  int_pem_sz ); chain_sz += int_pem_sz;
        write_file("out/chain_cert.pem", chain, chain_sz);

        FILE *h = fopen("out/certs_pqc.h", "w");
        if (!h) { perror("out/certs_pqc.h"); exit(1); }
        fprintf(h,
            "/* Auto-generated by gen_pq_chain_wolfssl  --  do not edit. */\n"
            "/* X9.146 dual-alg 3-level chain:                           */\n"
            "/*   primary = %s                                           */\n"
            "/*   alt     = ECDSA-P256/SHA-256                           */\n"
            "/* Root -> Intermediate -> Leaf (CN=192.168.0.100)          */\n"
            "#ifndef CERTS_PQC_H\n#define CERTS_PQC_H\n\n"
            "#define CERTS_PQC_PRIMARY_NAME \"%s\"\n"
            "#define CERTS_PQC_PRIMARY_LEVEL %d\n\n",
            PQ_NAME, PQ_NAME, PQ_LEVEL);
        emit_c_array(h, "chain_cert_pem", chain, chain_sz);
        emit_c_array(h, "leaf_key_der",   leaf_key_der, leaf_key_der_sz);
        fprintf(h, "#endif /* CERTS_PQC_H */\n");
        fclose(h);
        printf("  wrote out/certs_pqc.h (chain %zu B + leaf key %d B)\n",
               chain_sz, leaf_key_der_sz);
    }

    /* ----- Cleanup ----------------------------------------------- */
    wc_dilithium_free(&root_pq);
    wc_dilithium_free(&int_pq);
    wc_dilithium_free(&leaf_pq);
    wc_ecc_free(&root_ecc);
    wc_ecc_free(&int_ecc);
    wc_ecc_free(&leaf_ecc);
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    printf("\nOK.  Copy out/certs_pqc.h to TLS_X9/Core/Inc/ and rebuild firmware.\n");
    printf("     Use out/root_cert.pem as the client's trust anchor: -A root_cert.pem\n");
    return 0;
}
