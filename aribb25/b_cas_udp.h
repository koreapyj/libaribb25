#ifndef B_CAS_UDP_H
#define B_CAS_UDP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "b_cas_card.h"
#if defined(_WIN32)
#  include <tchar.h>
#else
#  define TCHAR char
#endif
extern B_CAS_CARD *create_b_cas_udp(const TCHAR *host, const TCHAR *port);

#ifdef __cplusplus
}
#endif

#endif /* B_CAS_UDP_H */
