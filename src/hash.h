#ifndef HASH_H_
#define HASH_H_

#include "autoconf.h"
#include "api/types.h"

typedef enum {
    HASH_TRANS_NODMA,
    HASh_TRANS_DMA,
} hash_transfert_mode_t;

typedef enum {
    HASH_MAP_THROUGH_CRYP,
    HASH_MAP_STANDALONE,
    HASH_MAP_STANDALONE_VOLUNTARY
} hash_map_mode_t;

typedef enum {
    HASH_POLL_MODE,
    HASH_IT_DIGEST_COMPLETE,
} hash_dev_mode_t;

typedef enum {
    HASH_REQ_IN_PROGRESS,
    HASH_REQ_LAST
} hash_req_type_t;

typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA224,
    HASH_SHA256,
    HASH_HMAC_SHA1,
    HASH_HMAC_SHA224,
    HASH_HMAC_SHA256,
} hash_algo_t;

typedef void (*cb_endofdigest)(uint32_t sr);
typedef void (*cb_endofdma)(uint32_t sr);


uint8_t hash_early_init(hash_transfert_mode_t transfert_mode,
                        hash_map_mode_t       map_mode,
                        hash_dev_mode_t       dev_mode);

uint8_t hash_init(cb_endofdigest eodigest_callback, cb_endofdma eodma_callback, hash_algo_t algo);

uint8_t hash_request(hash_req_type_t type, uint32_t addr, uint32_t size);

uint8_t hash_finalize(void);

#endif/*!HASH_H_*/
