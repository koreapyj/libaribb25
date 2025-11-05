#include "b_cas_card.h"
#include "b_cas_card_error_code.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <math.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <errno.h>
#  define _ftprintf fprintf
#  define GetAddrInfo getaddrinfo
#  define FreeAddrInfo freeaddrinfo
#  define ADDRINFOT struct addrinfo
#  define gai_strerrorA gai_strerror
#  define SOCKET int
#  define INVALID_SOCKET -1
#  if defined(DEBUG)
#    include <stdio.h>
#  endif
#  define _tcslen strlen
#  define _tcscmp strcmp
#  define _tcscpy strcpy
#  define _T(x) x
#endif

#if defined(_WIN32)
	// ref: https://stackoverflow.com/a/6924293/17124142
	EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#endif

void DumpHex(const TCHAR* prefix, uint8_t* data, size_t size) {
	size_t i;
	_ftprintf(stderr, _T("\r%s: <Buffer(%zu) "), prefix, size);
	for (i = 0; i < size; ++i) {
		_ftprintf(stderr, _T("%02X "), data[i]);
	}
	_ftprintf(stderr, _T(">\r\n"));
	fflush(stderr);
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 inner structures
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
typedef struct {
	SOCKET 					sock;
	const TCHAR	   *host;
	const TCHAR	   *port;

	uint8_t                *pool;

	uint8_t                *sbuf;
	uint8_t                *rbuf;

	B_CAS_INIT_STATUS       stat;
} B_CAS_CARD_PRIVATE_DATA;

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 constant values
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static const uint8_t CARD_ID_INFORMATION_FIXED[] = {
	0x00, 0x01, 0xb6, 0x17, 0x6c, 0xe0, 0x00, 0x00, 0x50, 0x45, 0x52, 0x46, 0x45, 0x43, 0x54, 0x56, 0x43, 0x4f, 0x4e, 0x44, 0x49, 0x54, 0x49, 0x4f, 0x4e, 0x41, 0x4c, 0x41, 0x43, 0x43, 0x45, 0x53, 0x53, 0x53, 0x59, 0x53, 0x54, 0x45, 0x4d, 0x31, 0x81, 0x01, 0x00, 0x00, 0x90, 0x00,
};

#define B_CAS_BUFFER_MAX (4*1024)

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 function prototypes (interface method)
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static void release_b_cas_udp(void *bcas);
static int init_b_cas_udp(void *bcas);
static int get_init_status_b_cas_udp(void *bcas, B_CAS_INIT_STATUS *stat);
static int get_id_b_cas_udp(void *bcas, B_CAS_ID *dst);
static int get_pwr_on_ctrl_b_cas_udp(void *bcas, B_CAS_PWR_ON_CTRL_INFO *dst);
static int proc_ecm_b_cas_udp(void *bcas, B_CAS_ECM_RESULT *dst, uint8_t *src, int len);
static int proc_emm_b_cas_udp(void *bcas, uint8_t *src, int len);

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 global function implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
B_CAS_CARD *create_b_cas_udp(const TCHAR *host, const TCHAR *port)
{
	int n;

	B_CAS_CARD *r;
	B_CAS_CARD_PRIVATE_DATA *prv;

	n = sizeof(B_CAS_CARD) + sizeof(B_CAS_CARD_PRIVATE_DATA);
	prv = (B_CAS_CARD_PRIVATE_DATA *)calloc(1, n);
	if(prv == NULL){
		return NULL;
	}

	r = (B_CAS_CARD *)(prv+1);

	r->private_data = prv;

	r->release = release_b_cas_udp;
	r->init = init_b_cas_udp;
	r->get_init_status = get_init_status_b_cas_udp;
	r->get_id = get_id_b_cas_udp;
	r->get_pwr_on_ctrl = get_pwr_on_ctrl_b_cas_udp;
	r->proc_ecm = proc_ecm_b_cas_udp;
	r->proc_emm = proc_emm_b_cas_udp;

	prv->host = host;
	prv->port = port;

	return r;
}


/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 function prototypes (private method)
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static B_CAS_CARD_PRIVATE_DATA *private_data(void *bcas);
static void teardown(B_CAS_CARD_PRIVATE_DATA *prv);
static int connect_card(B_CAS_CARD_PRIVATE_DATA *prv, void* reader_name);
static int32_t load_be_uint16(uint8_t *p);
static int64_t load_be_uint48(uint8_t *p);

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 interface method implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static void release_b_cas_udp(void *bcas)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if(prv == NULL){
		/* do nothing */
		return;
	}

	teardown(prv);
	free(prv);
}

static int init_b_cas_udp(void *bcas)
{
	int m;
	int ret;

	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if(prv == NULL){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	teardown(prv);

#if defined(_WIN32)
	WSADATA wsaData;
	ret = WSAStartup(MAKEWORD(2,2), &wsaData);
	if(ret != 0){
		return B_CAS_CARD_ERROR_NO_SMART_CARD_READER;
	}
#endif

	ADDRINFOT hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = 0,
		.ai_protocol = 0,
	};
	ADDRINFOT *result = NULL, *rp = NULL;
	if((ret = GetAddrInfo(prv->host, prv->port, &hints, &result))) {
		fprintf(stderr, "B_CAS_UDP: failed on getaddrinfo() : %s\n", gai_strerrorA(ret));
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		prv->sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (prv->sock == -1)
			continue;

		if (connect(prv->sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(prv->sock);
	}

	FreeAddrInfo(result);
	if (rp == NULL) {
		_ftprintf(stderr, _T("B_CAS_UDP: failed to connect to server\n"));
		return B_CAS_CARD_ERROR_ALL_READERS_CONNECTION_FAILED;
	}

	m = (2*B_CAS_BUFFER_MAX) + (sizeof(int64_t)*16) + (sizeof(B_CAS_PWR_ON_CTRL)*16);
	prv->pool = (uint8_t *)malloc(m);
	if(prv->pool == NULL){
		return B_CAS_CARD_ERROR_NO_ENOUGH_MEMORY;
	}

	prv->sbuf = prv->pool;
	prv->rbuf = prv->sbuf + B_CAS_BUFFER_MAX;

	if(connect_card(prv, NULL)){
#if defined(_WIN32)
		OutputDebugString(TEXT("libaribb25: connected card reader name:"));
#elif defined(DEBUG)
		_ftprintf(stderr, _T("libaribb25: connected\n"));
#endif
		return 0;
	}

	return B_CAS_CARD_ERROR_ALL_READERS_CONNECTION_FAILED;
}

static int get_init_status_b_cas_udp(void *bcas, B_CAS_INIT_STATUS *stat)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) || (stat == NULL) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->sock == INVALID_SOCKET){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	memcpy(stat, &(prv->stat), sizeof(B_CAS_INIT_STATUS));

	return 0;
}


static int get_id_b_cas_udp(void *bcas, B_CAS_ID *dst)
{
	return B_CAS_CARD_ERROR_INVALID_PARAMETER;
}

static int get_pwr_on_ctrl_b_cas_udp(void *bcas, B_CAS_PWR_ON_CTRL_INFO *dst)
{
	return B_CAS_CARD_ERROR_INVALID_PARAMETER;
}

static int proc_ecm_b_cas_udp(void *bcas, B_CAS_ECM_RESULT *dst, uint8_t *src, int len)
{
	int ret;
	unsigned long rlen;

	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) ||
			(dst == NULL) ||
			(src == NULL) ||
			(len < 1) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->sock == INVALID_SOCKET){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	DumpHex(_T("issue"), src, len);
	if((ret = send(prv->sock, src, len, 0)) != len) {
		if(ret == -1) {
			fprintf(stderr, "\rB_CAS_UDP: send failed (%s)\r\n", strerror(errno));
		}
		else {
			fprintf(stderr, "\rB_CAS_UDP: send failed - length mismatch (expected %d bytes, real %d bytes)\r\n", len, ret);
		}
		return B_CAS_CARD_ERROR_TRANSMIT_FAILED;
	}

	if((rlen = recv(prv->sock, prv->rbuf, B_CAS_BUFFER_MAX, NULL)) == -1) {
		fprintf(stderr, "\rB_CAS_UDP: read failed (%s)\r\n", strerror(errno));
		return B_CAS_CARD_ERROR_TRANSMIT_FAILED;
	}
	DumpHex(_T("resp"), prv->rbuf, rlen);

#ifdef ENABLE_ARIB_STD_B1
 	// 結果の判定方法を変更
 	if( (rlen == 0) ){
#else
	if( (rlen == 0) || (rlen < 25) ){
#endif
		fprintf(stderr, "\rB_CAS_UDP: read failed - length %ld\r\n", rlen);
		return B_CAS_CARD_ERROR_TRANSMIT_FAILED;
	}

#ifdef ENABLE_ARIB_STD_B1
 	if(rlen < 22){
 		dst->return_code = 0xa103;
 	}else{
 		const static uint8_t ffff[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
 		memcpy(dst->scramble_key, prv->rbuf, 16);
 		switch (load_be_uint16(prv->rbuf+18)){
		case 0xc001:
			dst->return_code = 0x0800;
			break;
		case 0xc000:
			dst->return_code = 0xa901;
			break;
		// 他にどんなコードがあるか不明なのでとりあえずff..ffかどうかでチェック
		default:
			if(!memcmp(dst->scramble_key, ffff, 16)){
				dst->return_code = 0xa902;
			}else{
				dst->return_code = 0x0800;
			}
			break;
 		}
 	}
#else
	memcpy(dst->scramble_key, prv->rbuf+6, 16);
	dst->return_code = load_be_uint16(prv->rbuf+4);
#endif

	return 0;
}

static int proc_emm_b_cas_udp(void *bcas, uint8_t *src, int len)
{
 	return B_CAS_CARD_ERROR_INVALID_PARAMETER;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 private method implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static B_CAS_CARD_PRIVATE_DATA *private_data(void *bcas)
{
	B_CAS_CARD_PRIVATE_DATA *r;
	B_CAS_CARD *p;

	p = (B_CAS_CARD *)bcas;
	if(p == NULL){
		return NULL;
	}

	r = (B_CAS_CARD_PRIVATE_DATA *)(p->private_data);
	if( ((void *)(r+1)) != ((void *)p) ){
		return NULL;
	}

	return r;
}

static void teardown(B_CAS_CARD_PRIVATE_DATA *prv)
{
	if(prv->sock) {
		close(prv->sock);
	}
#if defined(_WIN32)
	WSACleanup();
#endif

	if(prv->pool != NULL){
		free(prv->pool);
		prv->pool = NULL;
	}

	prv->sbuf = NULL;
	prv->rbuf = NULL;
}

static int connect_card(B_CAS_CARD_PRIVATE_DATA *prv, void *reader_name)
{
	int n;
	unsigned long rlen;
	uint8_t *p;

	rlen = sizeof(CARD_ID_INFORMATION_FIXED);
	memcpy(prv->rbuf, CARD_ID_INFORMATION_FIXED, rlen);

#ifdef ENABLE_ARIB_STD_B1
	if(rlen < 46){
#else
	if(rlen < 57){
#endif
		return 0;
	}

	p = prv->rbuf;

#ifdef ENABLE_ARIB_STD_B1
 	n = load_be_uint16(p+44);
 	if(n != 0x9000){ // return code missmatch
 		// 最終2バイトがリターンコードかどうか未確認なのでエラーとはしない
 		// return 0;
	}
#else
	n = load_be_uint16(p+4);
	if(n != 0x2100){ // return code missmatch
		return 0;
	}
#endif

#ifdef ENABLE_ARIB_STD_B1
	memcpy(prv->stat.system_key, p+8, 32);
	memcpy(prv->stat.init_cbc, p+8, 8);
	prv->stat.ca_system_id = load_be_uint16(p);
	prv->stat.card_status = 0;
#else
	memcpy(prv->stat.system_key, p+16, 32);
	memcpy(prv->stat.init_cbc, p+48, 8);
	prv->stat.bcas_card_id = load_be_uint48(p+8);
	prv->stat.card_status = load_be_uint16(p+2);
	prv->stat.ca_system_id = load_be_uint16(p+6);
#endif

	return 1;
}

static int32_t load_be_uint16(uint8_t *p)
{
	return ((p[0]<<8)|p[1]);
}

static int64_t load_be_uint48(uint8_t *p)
{
	int i;
	int64_t r;

	r = p[0];
	for(i=1;i<6;i++){
		r <<= 8;
		r |= p[i];
	}

	return r;
}
