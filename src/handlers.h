#ifndef HANDLERS_H
#define HANDLERS_H

#include "libc/types.h"

extern volatile status_reg_t status_reg;

void hash_dma_cb(uint8_t irq, uint32_t status);

void hash_eodigest_cb(uint8_t irq, uint32_t status);

#endif
