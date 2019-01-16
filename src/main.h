#ifndef MAIN_H_
# define MAIN_H_

#define SMART_DEBUG 0
#include "automaton.h"

typedef struct {
    bool dma_done;
    bool dma_hdone;
    bool dma_fifo_err;
    bool dma_dm_err;
    bool dma_tr_err;
} status_reg_t;

#endif/*!MAIN_H_*/
