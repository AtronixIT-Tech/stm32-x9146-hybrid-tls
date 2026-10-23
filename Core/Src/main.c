/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "string.h"
#include "lwip.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <stdlib.h>
#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include "lwip/err.h"

/* wolfSSL */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfio.h"

/* --- Compile-time assertions that the Dilithium private-key decode
 *     path is actually enabled in this build. If any of these fire,
 *     wolfSSL_CTX_use_PrivateKey_buffer would silently return -463
 *     regardless of the key bytes. ---------------------------------- */
#if !defined(HAVE_DILITHIUM)
#  error "HAVE_DILITHIUM is not defined (check WOLF_CONF_MLDSA)"
#endif
#if defined(WOLFSSL_DILITHIUM_NO_SIGN)
#  error "WOLFSSL_DILITHIUM_NO_SIGN is defined -> sign/private-key path disabled"
#endif
#if defined(WOLFSSL_DILITHIUM_NO_ASN1)
#  error "WOLFSSL_DILITHIUM_NO_ASN1 is defined -> private-key decoder disabled"
#endif
#if defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
#  error "WOLFSSL_DILITHIUM_VERIFY_ONLY is defined -> private-key decoder disabled"
#endif

/* 3-level ML-DSA-44 cert chain, embedded as C arrays */
#include "certs_pqc.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* Set to 1 to run wolfCrypt primitive benchmarks instead of TLS server.
 * Flash, capture UART, then set back to 0 for normal TLS operation.
 * Run once with WOLF_CONF_MATH=6/ARMASM=0, once with MATH=4/ARMASM=1. */
#define RUN_WOLFCRYPT_BENCH  0

/* Set to 1 to clock at 272 MHz (PLLN=136) instead of 550 MHz (PLLN=275).
 * Use only with RUN_WOLFCRYPT_BENCH=1. Restore to 0 for TLS operation. */
#define BENCH_CLOCK_272  0

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* ETH handle, DMA descriptor tables, and TxConfig are owned by LWIP/Target/ethernetif.c */

COM_InitTypeDef BspCOMInit;
__IO uint32_t BspButtonState = BUTTON_RELEASED;

RNG_HandleTypeDef hrng;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MPU_Config(void);
static void MX_GPIO_Init(void);
static void MX_RNG_Init(void);
/* USER CODE BEGIN PFP */
static void tls_server_init(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* Required by wolfCrypt benchmark.c on bare-metal targets. */
double current_time(int reset)
{
    (void)reset;
    return (double)HAL_GetTick() / 1000.0;
}

/* ============================================================================
 *  wolfSSL TLS 1.3 server on port 443 (Step 3).
 *
 *  Uses the wolfSSL raw I/O callbacks on top of lwIP raw-API tcp_pcb.
 *  Presents a 3-level ML-DSA-44 chain (Root -> Intermediate -> Leaf) where
 *  the Leaf CN=192.168.0.100. Server sends Intermediate+Leaf; the MSYS2
 *  client is expected to trust the Root out of band.
 * ============================================================================ */

/* One WOLFSSL_CTX is shared by all connections. */
static WOLFSSL_CTX *tls_ctx = NULL;

/* One active connection at a time (single-threaded, no RTOS). */
typedef struct tls_conn
{
  struct tcp_pcb *pcb;
  WOLFSSL        *ssl;

  /* Queue of inbound pbufs not yet consumed by wolfSSL_read()/accept(). */
  struct pbuf    *rx_head;    /* current pbuf being drained */
  u16_t           rx_offset;  /* byte offset within rx_head->payload */

  uint8_t         handshake_done;
  uint8_t         closing;

  /* Benchmark: DWT cycle count captured at TCP accept (connection t0). */
  uint32_t        hs_start_cyc;

  /* Phase timing: five-point breakdown per handshake.
   *   cyc_ch   = ClientHello fully received (first type-22 read)
   *   cyc_sh   = ServerHello queued        (first type-22 write)
   *   cyc_cert = Cert flight queued        (last  type-23 write)
   * Intervals:
   *   CH-SH   = cyc_sh   - cyc_start
   *   SH-Cert = cyc_cert - cyc_sh
   *   Cert-Fin= hs_done  - cyc_cert        (includes network + client)   */
  uint32_t        cyc_ch;
  uint32_t        cyc_sh;
  uint32_t        cyc_cert;
  uint8_t         cyc_ch_set;
  uint8_t         cyc_sh_set;
} tls_conn_t;

/* --------- Handshake benchmark (Step 4) --------------------------------- */
/* 1000-HS run with PHASE_TIMING=1 gives both stats and phase data. */
#define HS_BENCH_TARGET   1000
#define PHASE_TIMING      1    /* 1 = print per-handshake phase intervals */

static uint32_t hs_count         = 0;
static uint64_t hs_sum_us_64     = 0;
static uint32_t hs_min_us        = 0xFFFFFFFFu;
static uint32_t hs_max_us        = 0;

#if PHASE_TIMING
static uint64_t phase_sum_ch_us  = 0;
static uint64_t phase_sum_sh_us  = 0;
static uint64_t phase_sum_ce_us  = 0;
static uint64_t phase_sum_fi_us  = 0;
#endif

/* Per-handshake timing array for median / P95 / P99 (4 KB at 1000 entries). */
static uint32_t hs_times_us[HS_BENCH_TARGET];

static int uint32_cmp(const void *a, const void *b)
{
  uint32_t x = *(const uint32_t *)a;
  uint32_t y = *(const uint32_t *)b;
  return (x > y) - (x < y);
}

/* DWT CYCCNT ticks at the core clock (550 MHz after SystemClock_Config).
 * 32-bit CYCCNT wraps at ~7.8 s, which is fine for a single handshake. */
#define DWT_HZ  550000000u  /* SYSCLK = 550 MHz after SystemClock_Config */

static void dwt_init(void)
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;   /* enable trace */
  DWT->LAR         = 0xC5ACCE55;                    /* unlock (optional on M7) */
  DWT->CYCCNT      = 0;
  DWT->CTRL       |= DWT_CTRL_CYCCNTENA_Msk;        /* start counter */
}

static inline uint32_t dwt_now(void)
{
  return DWT->CYCCNT;
}

static inline uint32_t dwt_elapsed_us(uint32_t start_cyc)
{
  /* Unsigned subtraction handles wrap. */
  uint32_t delta = DWT->CYCCNT - start_cyc;
  return delta / (DWT_HZ / 1000000u);   /* cycles -> microseconds */
}

/* --------- wolfSSL custom I/O callbacks ---------------------------------- */

static int tls_recv_io(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
  (void)ssl;
  tls_conn_t *c = (tls_conn_t *)ctx;

  if (c->rx_head == NULL)
  {
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }

  int copied = 0;
  while (sz > 0 && c->rx_head != NULL)
  {
    struct pbuf *p = c->rx_head;
    int avail = (int)p->len - (int)c->rx_offset;

    if (avail == 0)
    {
      /* Advance to next sibling pbuf, free this one. */
      c->rx_head = p->next;
      p->next = NULL;                      /* prevent chain free */
      tcp_recved(c->pcb, p->len);
      pbuf_free(p);
      c->rx_offset = 0;
      continue;
    }

    int take = (avail < sz) ? avail : sz;
    memcpy(buf + copied, (uint8_t *)p->payload + c->rx_offset, take);
    c->rx_offset += (u16_t)take;
    copied += take;
    sz     -= take;
  }

  if (copied == 0)
  {
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }

  /* First data received = ClientHello arriving. */
  if (!c->cyc_ch_set) {
    c->cyc_ch     = dwt_now();
    c->cyc_ch_set = 1;
  }
  return copied;
}

static int tls_send_io(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
  (void)ssl;
  tls_conn_t *c = (tls_conn_t *)ctx;

  u16_t sndbuf = tcp_sndbuf(c->pcb);
  if (sndbuf == 0)
  {
    return WOLFSSL_CBIO_ERR_WANT_WRITE;
  }

  int take = (sz < (int)sndbuf) ? sz : (int)sndbuf;
  err_t e = tcp_write(c->pcb, buf, (u16_t)take, TCP_WRITE_FLAG_COPY);
  if (e != ERR_OK)
  {
    if (e == ERR_MEM) return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
  tcp_output(c->pcb);

  /* First send = ServerHello; every subsequent send updates cyc_cert so
   * the last value captured is the cert flight / Finished queued time.  */
  if (!c->cyc_sh_set) {
    c->cyc_sh     = dwt_now();
    c->cyc_sh_set = 1;
  }
  c->cyc_cert = dwt_now();

  return take;
}

/* --------- Pump: drive accept() and/or read-echo ------------------------- */

static void tls_conn_pump(tls_conn_t *c)
{
  if (c->closing) return;

  if (!c->handshake_done)
  {
    int r = wolfSSL_accept(c->ssl);
    if (r == WOLFSSL_SUCCESS)
    {
      uint32_t cyc_fin = dwt_now();
      uint32_t us      = dwt_elapsed_us(c->hs_start_cyc);
      c->handshake_done = 1;

      /* Update benchmark stats. */
      if (hs_count < HS_BENCH_TARGET)
        hs_times_us[hs_count] = us;
      hs_count += 1;
      hs_sum_us_64 += us;
      if (us < hs_min_us) hs_min_us = us;
      if (us > hs_max_us) hs_max_us = us;

      const char *v = wolfSSL_get_version(c->ssl);
      const char *s = wolfSSL_get_cipher(c->ssl);
      printf("  [tls] HANDSHAKE #%lu OK  %lu.%03lu ms  version=%s  suite=%s\r\n",
             (unsigned long)hs_count,
             (unsigned long)(us / 1000u), (unsigned long)(us % 1000u),
             v ? v : "?", s ? s : "?");

#if PHASE_TIMING
      /* Print five-point phase breakdown.  All times relative to hs_start_cyc.
       * Output one CSV line per handshake for easy offline parsing:
       *   PHASE N  total_us  ch_us  sh_us  cert_us  fin_us              */
      {
        uint32_t t0   = c->hs_start_cyc;
        uint32_t t_ch = c->cyc_ch_set ? (uint32_t)((uint64_t)(c->cyc_ch   - t0) * 1000000u / DWT_HZ) : 0;
        uint32_t t_sh = c->cyc_sh_set ? (uint32_t)((uint64_t)(c->cyc_sh   - t0) * 1000000u / DWT_HZ) : 0;
        uint32_t t_ce = c->cyc_cert   ? (uint32_t)((uint64_t)(c->cyc_cert - t0) * 1000000u / DWT_HZ) : 0;
        uint32_t t_fi = (uint32_t)((uint64_t)(cyc_fin - t0) * 1000000u / DWT_HZ);
        printf("PHASE %lu  %lu  %lu  %lu  %lu  %lu\r\n",
               (unsigned long)hs_count,
               (unsigned long)us,
               (unsigned long)t_ch,
               (unsigned long)t_sh,
               (unsigned long)t_ce,
               (unsigned long)t_fi);
        phase_sum_ch_us += t_ch;
        phase_sum_sh_us += t_sh;
        phase_sum_ce_us += t_ce;
        phase_sum_fi_us += t_fi;
      }
#endif /* PHASE_TIMING */

      if (hs_count == HS_BENCH_TARGET)
      {
        uint64_t avg_us = hs_sum_us_64 / hs_count;

        /* Sort the timing array to derive percentiles. */
        qsort(hs_times_us, HS_BENCH_TARGET, sizeof(hs_times_us[0]), uint32_cmp);
        uint32_t p50_us = hs_times_us[HS_BENCH_TARGET / 2];
        uint32_t p95_us = hs_times_us[(uint32_t)(HS_BENCH_TARGET * 95u / 100u)];
        uint32_t p99_us = hs_times_us[(uint32_t)(HS_BENCH_TARGET * 99u / 100u)];

        printf("\r\n=============================================================\r\n");
        printf(" HANDSHAKE BENCHMARK SUMMARY (%lu handshakes)\r\n",
               (unsigned long)hs_count);
        printf("   min    = %lu.%03lu ms\r\n",
               (unsigned long)(hs_min_us / 1000u),
               (unsigned long)(hs_min_us % 1000u));
        printf("   mean   = %lu.%03lu ms\r\n",
               (unsigned long)((uint32_t)avg_us / 1000u),
               (unsigned long)((uint32_t)avg_us % 1000u));
        printf("   median = %lu.%03lu ms\r\n",
               (unsigned long)(p50_us / 1000u),
               (unsigned long)(p50_us % 1000u));
        printf("   P95    = %lu.%03lu ms\r\n",
               (unsigned long)(p95_us / 1000u),
               (unsigned long)(p95_us % 1000u));
        printf("   P99    = %lu.%03lu ms\r\n",
               (unsigned long)(p99_us / 1000u),
               (unsigned long)(p99_us % 1000u));
        printf("   max    = %lu.%03lu ms\r\n",
               (unsigned long)(hs_max_us / 1000u),
               (unsigned long)(hs_max_us % 1000u));
        printf("   sig    = %s (Dilithium level %d)\r\n",
               CERTS_PQC_PRIMARY_NAME, CERTS_PQC_PRIMARY_LEVEL);
#if PHASE_TIMING
        {
          uint32_t ph_ch = (uint32_t)(phase_sum_ch_us  / hs_count);
          uint32_t ph_sh = (uint32_t)(phase_sum_sh_us  / hs_count);
          uint32_t ph_ce = (uint32_t)(phase_sum_ce_us  / hs_count);
          uint32_t ph_fi = (uint32_t)(phase_sum_fi_us  / hs_count);
          printf("   --- mean phase breakdown (us) ---\r\n");
          printf("   t0->CH   = %lu\r\n",  (unsigned long)ph_ch);
          printf("   CH->SH   = %lu\r\n",  (unsigned long)(ph_sh - ph_ch));
          printf("   SH->Cert = %lu\r\n",  (unsigned long)(ph_ce - ph_sh));
          printf("   Cert->Fin= %lu\r\n",  (unsigned long)(ph_fi - ph_ce));
          printf("   phase mean total = %lu.%03lu ms\r\n",
                 (unsigned long)(ph_fi / 1000u),
                 (unsigned long)(ph_fi % 1000u));
        }
#endif
        printf("=============================================================\r\n\r\n");
      }
    }
    else
    {
      int err = wolfSSL_get_error(c->ssl, r);
      if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
      {
        char ebuf[80] = {0};
        wolfSSL_ERR_error_string((unsigned long)err, ebuf);
        printf("  [tls] handshake FAIL err=%d (%s)\r\n", err, ebuf);
        c->closing = 1;
      }
    }
  }

  if (c->handshake_done && !c->closing)
  {
    /* Application layer: echo whatever plaintext arrives. */
    char app[256];
    int n = wolfSSL_read(c->ssl, app, sizeof(app));
    if (n > 0)
    {
      printf("  [tls] app rx %d bytes, echoing\r\n", n);
      (void)wolfSSL_write(c->ssl, app, n);
    }
    else if (n == 0)
    {
      c->closing = 1;
    }
    else
    {
      int err = wolfSSL_get_error(c->ssl, n);
      if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
      {
        printf("  [tls] read err=%d\r\n", err);
        c->closing = 1;
      }
    }
  }
}

/* --------- lwIP tcp_pcb callbacks ---------------------------------------- */

static void tls_conn_free(tls_conn_t *c)
{
  if (c == NULL) return;

  if (c->ssl)       { wolfSSL_free(c->ssl);         c->ssl = NULL; }
  if (c->rx_head)   { pbuf_free(c->rx_head);        c->rx_head = NULL; }
  free(c);
}

static err_t tls_recv_cb(void *arg, struct tcp_pcb *tpcb,
                         struct pbuf *p, err_t err)
{
  tls_conn_t *c = (tls_conn_t *)arg;

  if (p == NULL)
  {
    /* Remote FIN */
    printf("  [tls] client FIN\r\n");
    tcp_arg(tpcb, NULL);
    tcp_close(tpcb);
    tls_conn_free(c);
    return ERR_OK;
  }
  if (err != ERR_OK)
  {
    pbuf_free(p);
    return err;
  }
  if (c == NULL)
  {
    pbuf_free(p);
    return ERR_VAL;
  }

  /* Append p onto the RX queue. */
  if (c->rx_head == NULL) c->rx_head = p;
  else                    pbuf_cat(c->rx_head, p);

  tls_conn_pump(c);

  if (c->closing)
  {
    tcp_arg(tpcb, NULL);
    tcp_close(tpcb);
    tls_conn_free(c);
  }
  return ERR_OK;
}

static err_t tls_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
  (void)len;
  tls_conn_t *c = (tls_conn_t *)arg;
  if (c == NULL) return ERR_OK;

  /* TX buffer drained a bit — may unblock a pending write/handshake. */
  tls_conn_pump(c);

  if (c->closing)
  {
    tcp_arg(tpcb, NULL);
    tcp_close(tpcb);
    tls_conn_free(c);
  }
  return ERR_OK;
}

static void tls_err_cb(void *arg, err_t err)
{
  tls_conn_t *c = (tls_conn_t *)arg;
  printf("  [tls] lwip err cb: %d\r\n", (int)err);
  /* lwIP has already freed the pcb by this point. */
  if (c) { c->pcb = NULL; tls_conn_free(c); }
}

static err_t tls_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
  (void)arg;
  if (err != ERR_OK || newpcb == NULL) return ERR_VAL;

  printf("  [tls] accept from %u.%u.%u.%u:%u\r\n",
         (unsigned)ip4_addr1(&newpcb->remote_ip),
         (unsigned)ip4_addr2(&newpcb->remote_ip),
         (unsigned)ip4_addr3(&newpcb->remote_ip),
         (unsigned)ip4_addr4(&newpcb->remote_ip),
         (unsigned)newpcb->remote_port);

  tls_conn_t *c = (tls_conn_t *)calloc(1, sizeof(*c));
  if (c == NULL)
  {
    printf("  [tls] calloc failed\r\n");
    tcp_close(newpcb);
    return ERR_MEM;
  }
  c->pcb = newpcb;

  c->ssl = wolfSSL_new(tls_ctx);
  if (c->ssl == NULL)
  {
    printf("  [tls] wolfSSL_new failed\r\n");
    free(c);
    tcp_close(newpcb);
    return ERR_MEM;
  }
  wolfSSL_SetIOReadCtx (c->ssl, c);
  wolfSSL_SetIOWriteCtx(c->ssl, c);
  /* Capture TCP-accept time as t0 for the five-point phase breakdown. */
  c->hs_start_cyc = dwt_now();

  tcp_arg (newpcb, c);
  tcp_recv(newpcb, tls_recv_cb);
  tcp_sent(newpcb, tls_sent_cb);
  tcp_err (newpcb, tls_err_cb);

  /* Disable Nagle on the accepted pcb.  TLS 1.3 flights don't align
   * to MSS; with Nagle on, the last sub-MSS segment of the server's
   * first flight waits for the peer's ACK and collides with the
   * peer's delayed-ACK timer (40-200 ms of pure wall-clock wait per
   * handshake).  Turn it off so segments go out immediately. */
  tcp_nagle_disable(newpcb);

  return ERR_OK;
}

/* --------- bring-up ------------------------------------------------------ */

static void tls_server_init(void)
{
  int ret;

  wolfSSL_Init();

  tls_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
  if (tls_ctx == NULL)
  {
    printf("  [tls] CTX_new failed\r\n");
    return;
  }

  /* Hook our raw-LwIP I/O on the CTX; per-SSL ctx pointers set at accept. */
  wolfSSL_SetIORecv(tls_ctx, tls_recv_io);
  wolfSSL_SetIOSend(tls_ctx, tls_send_io);

  /* Server cert chain (PEM, leaf first then intermediate). */
  ret = wolfSSL_CTX_use_certificate_chain_buffer(tls_ctx,
                                                 chain_cert_pem,
                                                 (long)chain_cert_pem_len);
  if (ret != WOLFSSL_SUCCESS)
  {
    printf("  [tls] load cert chain failed %d\r\n", ret);
    return;
  }

  /* Leaf private key (DER/PKCS#8). */
  ret = wolfSSL_CTX_use_PrivateKey_buffer(tls_ctx,
                                          leaf_key_der, (long)leaf_key_der_len,
                                          WOLFSSL_FILETYPE_ASN1);
  if (ret != WOLFSSL_SUCCESS)
  {
    printf("  [tls] load leaf key failed %d\r\n", ret);
    return;
  }

  /* Skip client cert verification. */
  wolfSSL_CTX_set_verify(tls_ctx, WOLFSSL_VERIFY_NONE, NULL);

  /* Bind TCP listen on :443 */
  struct tcp_pcb *pcb = tcp_new();
  if (pcb == NULL) { printf("  [tls] tcp_new failed\r\n"); return; }
  if (tcp_bind(pcb, IP_ANY_TYPE, 443) != ERR_OK)
  {
    printf("  [tls] tcp_bind :443 failed\r\n");
    tcp_close(pcb);
    return;
  }
  struct tcp_pcb *lpcb = tcp_listen(pcb);
  if (lpcb == NULL) { printf("  [tls] tcp_listen failed\r\n"); return; }
  tcp_accept(lpcb, tls_accept_cb);

  printf("  [tls] TLS 1.3 server listening on :443 (%s chain)\r\n",
         CERTS_PQC_PRIMARY_NAME);
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MPU Configuration--------------------------------------------------------*/
  MPU_Config();

  /* Enable Cortex-M7 I-cache and D-cache.  MPU has already marked
   * RAM_D2 @ 0x30000000 (ETH DMA descriptors / RX pool) as
   * non-cacheable, so the DCache is safe to turn on.  Caches are the
   * single biggest handshake-latency win on M7 — ML-DSA / SHAKE /
   * AES-GCM all speed up 3-5x. */
  SCB_EnableICache();
  SCB_EnableDCache();

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */
  /* Enable precise fault handlers (MemManage / BusFault / UsageFault).
   * Without this, everything escalates to HardFault and we lose the
   * precise cause. Do NOT enable UNALIGN_TRP (CCR bit 3) — the Cortex-M7
   * handles unaligned loads natively and lwIP relies on that for
   * IP/TCP header parsing at odd offsets. DIV_0_TRP (bit 4) is fine. */
  SCB->SHCSR |= (1u << 16) | (1u << 17) | (1u << 18);
  SCB->CCR   |= (1u << 4);
  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_RNG_Init();
  /* USER CODE BEGIN 2 */

  /* USER CODE END 2 */

  /* Initialize leds */
  BSP_LED_Init(LED_GREEN);
  BSP_LED_Init(LED_YELLOW);
  BSP_LED_Init(LED_RED);

  /* Initialize USER push-button, will be used to trigger an interrupt each time it's pressed.*/
  BSP_PB_Init(BUTTON_USER, BUTTON_MODE_EXTI);

  /* Initialize COM1 port (115200, 8 bits (7-bit data + 1 stop bit), no parity */
  BspCOMInit.BaudRate   = 115200;
  BspCOMInit.WordLength = COM_WORDLENGTH_8B;
  BspCOMInit.StopBits   = COM_STOPBITS_1;
  BspCOMInit.Parity     = COM_PARITY_NONE;
  BspCOMInit.HwFlowCtl  = COM_HWCONTROL_NONE;
  if (BSP_COM_Init(COM1, &BspCOMInit) != BSP_ERROR_NONE)
  {
    Error_Handler();
  }

  /* USER CODE BEGIN BSP */

  /* -- Sample board code to send message over COM1 port ---- */
  printf("\r\n=== BOOT OK (USART3 115200) ===\r\n");

  /* Build configuration banner (mirrors KYBER firmware for reproducibility). */
  printf("--- TLS_X9 Build Config ---\r\n");
#if defined(WOLFSSL_ARMASM)
  printf("  WOLFSSL_ARMASM : YES\r\n");
#else
  printf("  WOLFSSL_ARMASM : NO\r\n");
#endif
#if defined(WOLFSSL_SP_ARM_CORTEX_M_ASM) || defined(WOLFSSL_SP_ASM)
  printf("  SP_ASM         : YES\r\n");
#else
  printf("  SP_ASM         : NO\r\n");
#endif
#if defined(WOLFSSL_DILITHIUM_SMALL)
  printf("  DILITHIUM_SMALL: YES\r\n");
#else
  printf("  DILITHIUM_SMALL: NO (large/fast path)\r\n");
#endif
  printf("  I-Cache        : %s\r\n",
         (SCB->CCR & SCB_CCR_IC_Msk) ? "ON" : "OFF");
  printf("  D-Cache        : %s\r\n",
         (SCB->CCR & SCB_CCR_DC_Msk) ? "ON" : "OFF");
  printf("  HS_BENCH_TARGET: %d\r\n", HS_BENCH_TARGET);
  printf("  PHASE_TIMING   : %s\r\n", PHASE_TIMING ? "YES" : "NO");
  printf("  Chain          : %s level %d\r\n",
         CERTS_PQC_PRIMARY_NAME, CERTS_PQC_PRIMARY_LEVEL);
  printf("  SYSCLK         : %s\r\n", BENCH_CLOCK_272 ? "272 MHz" : "550 MHz");
  printf("---------------------------\r\n");

  /* -- Sample board code to switch on leds ---- */
  BSP_LED_On(LED_GREEN);
  BSP_LED_On(LED_YELLOW);
  BSP_LED_On(LED_RED);

#if RUN_WOLFCRYPT_BENCH
  {
    extern int benchmark_test(void *);
    dwt_init();
    printf("\r\n=== wolfCrypt benchmark START ===\r\n");
    benchmark_test(NULL);
    printf("=== wolfCrypt benchmark END ===\r\n");
    while (1) { BSP_LED_Toggle(LED_GREEN); HAL_Delay(500); }
  }
#endif


  /* Bring up LwIP (this calls HAL_ETH_Init + LAN8742 init inside ethernetif_init) */
  MX_LWIP_Init();
  printf("LwIP initialised, IP = 192.168.0.100\r\n");

  /* Step 4: enable DWT cycle counter for handshake benchmarking. */
  dwt_init();

  /* Step 3: wolfSSL TLS 1.3 server on port 443 with ML-DSA-44 chain */
  tls_server_init();

  /* USER CODE END BSP */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  uint32_t last_tick = HAL_GetTick();
  uint32_t counter = 0;
  while (1)
  {

    /* -- Sample board code for User push-button in interrupt mode ---- */
    if (BspButtonState == BUTTON_PRESSED)
    {
      /* Update button state */
      BspButtonState = BUTTON_RELEASED;
      /* -- Sample board code to toggle leds ---- */
      BSP_LED_Toggle(LED_GREEN);
      BSP_LED_Toggle(LED_YELLOW);
      BSP_LED_Toggle(LED_RED);

      /* ..... Perform your action ..... */
    }
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
    /* Drive the LwIP stack: pull RX packets up, run timers, check PHY link */
    MX_LWIP_Process();

    /* Heartbeat: print once per second + toggle green LED + print netif status */
    if (HAL_GetTick() - last_tick >= 1000u)
    {
      last_tick = HAL_GetTick();
      counter++;
      printf("tick #%lu  uptime %lu s  ", (unsigned long)counter,
             (unsigned long)(HAL_GetTick() / 1000u));
      MX_LWIP_PrintStatus();
      BSP_LED_Toggle(LED_GREEN);
    }
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Supply configuration update enable
  */
  HAL_PWREx_ConfigSupply(PWR_LDO_SUPPLY);

  /** Configure the main internal regulator output voltage
  */
  /* VOS0 is required for SYSCLK > 400 MHz on STM32H723.  LDO supply plus
   * PWR_REGULATOR_VOLTAGE_SCALE0 lets us clock the core at the full
   * 550 MHz spec. */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE0);

  while(!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {}

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  *
  * Target: SYSCLK = 550 MHz (H723 max).
  *   HSI = 64 MHz
  *   PLLM = 32  -> ref  = 2  MHz   (range _1: 2-4 MHz, wide VCO)
  *   PLLN = 275 -> VCO  = 550 MHz  (wide range 192-836 MHz)
  *   PLLP = 1   -> P    = 550 MHz  -> SYSCLK
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI|RCC_OSCILLATORTYPE_HSI48;
  RCC_OscInitStruct.HSIState = RCC_HSI_DIV1;
  RCC_OscInitStruct.HSICalibrationValue = 64;
  RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 32;
#if BENCH_CLOCK_272
  RCC_OscInitStruct.PLL.PLLN = 136;  /* 2 MHz * 136 = 272 MHz SYSCLK */
#else
  RCC_OscInitStruct.PLL.PLLN = 275;  /* 2 MHz * 275 = 550 MHz SYSCLK */
#endif
  RCC_OscInitStruct.PLL.PLLP = 1;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  RCC_OscInitStruct.PLL.PLLR = 2;
  RCC_OscInitStruct.PLL.PLLRGE = RCC_PLL1VCIRANGE_1;
  RCC_OscInitStruct.PLL.PLLVCOSEL = RCC_PLL1VCOWIDE;
  RCC_OscInitStruct.PLL.PLLFRACN = 0;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  *
  * SYSCLK = 550 MHz, HCLK = 275 MHz (AXI/AHB max at VOS0),
  * PCLK1/2/3/4 = 137.5 MHz (APB max = HCLK/2).
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2
                              |RCC_CLOCKTYPE_D3PCLK1|RCC_CLOCKTYPE_D1PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.SYSCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_APB3_DIV2;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_APB1_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_APB2_DIV2;
  RCC_ClkInitStruct.APB4CLKDivider = RCC_APB4_DIV2;

  /* VOS0, HCLK 210-275 MHz requires 3 wait states per RM0468 Table 16.
   * Use FLASH_LATENCY_4 for margin (still within the VOS0 allowable
   * range and the HAL programs WRHIGHFREQ accordingly). */
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK)
  {
    Error_Handler();
  }

  /* STM32H7 requires an explicit kernel clock selection for the RNG. The
   * cube-generated code enables HSI48 but never routes it to the RNG
   * domain, so the first read of RNG->DR raises an IMPRECISE bus fault.
   * wolfCrypt hits this inside wc_RNG_GenerateBlock during the first
   * wolfSSL_accept. Route HSI48 -> RNG here. */
  {
    RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};
    PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_RNG;
    PeriphClkInit.RngClockSelection    = RCC_RNGCLKSOURCE_HSI48;
    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
    {
      Error_Handler();
    }
    __HAL_RCC_RNG_CLK_ENABLE();
  }
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{
  hrng.Instance = RNG;
  hrng.Init.ClockErrorDetection = RNG_CED_ENABLE;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

 /* MPU Configuration */

void MPU_Config(void)
{
  MPU_Region_InitTypeDef MPU_InitStruct = {0};

  /* Disables the MPU */
  HAL_MPU_Disable();

  /** Initializes and configures the Region and the memory to be protected
  */
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER0;
  MPU_InitStruct.BaseAddress = 0x0;
  MPU_InitStruct.Size = MPU_REGION_SIZE_4GB;
  MPU_InitStruct.SubRegionDisable = 0x87;
  MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL0;
  MPU_InitStruct.AccessPermission = MPU_REGION_NO_ACCESS;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_SHAREABLE;
  MPU_InitStruct.IsCacheable = MPU_ACCESS_NOT_CACHEABLE;
  MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  /* Region 1: RAM_D2 (0x30000000, 32KB) — Ethernet DMA descriptors + RX pool.
   * Must be non-cacheable so Ethernet DMA and CPU see the same data. */
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER1;
  MPU_InitStruct.BaseAddress = 0x30000000;
  MPU_InitStruct.Size = MPU_REGION_SIZE_32KB;
  MPU_InitStruct.SubRegionDisable = 0x00;
  MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL1;
  MPU_InitStruct.AccessPermission = MPU_REGION_FULL_ACCESS;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;
  MPU_InitStruct.IsCacheable = MPU_ACCESS_NOT_CACHEABLE;
  MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  /* Enables the MPU */
  HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);

}

/**
  * @brief BSP Push Button callback
  * @param Button Specifies the pressed button
  * @retval None
  */
void BSP_PB_Callback(Button_TypeDef Button)
{
  if (Button == BUTTON_USER)
  {
    BspButtonState = BUTTON_PRESSED;
  }
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
