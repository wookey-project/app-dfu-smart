#ifndef __DFU_HEADER_H__
#define __DFU_HEADER_H__

#include "api/types.h"

/* Include libecc headers for the crypto part 
 * (asymmetric ECC and hash functions).
 */
#include "libsig.h"

typedef enum {
	FLIP = 0,
	FLOP = 1,
} partitions_types;

typedef struct __packed {
	uint32_t magic;
	uint32_t type;
	uint32_t version;
	uint32_t len;
	uint32_t siglen;
	uint32_t chunksize;
	uint8_t iv[16];
	uint8_t hmac[32];
	/* The signature goes here ... with a siglen length */
} dfu_update_header_t;

int dfu_parse_header(uint8_t *buffer, uint32_t len, dfu_update_header_t *header, uint8_t *sig, uint32_t siglen);

void dfu_print_header(dfu_update_header_t *header);

#endif /* __DFU_HEADER_H__ */
