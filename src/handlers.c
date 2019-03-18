#include "api/stdio.h"
#include "api/nostd.h"
#include "api/types.h"
#include "api/syscall.h"
#include "main.h"

volatile status_reg_t status_reg = { 0 }; 

void hash_dma_cb(__attribute__((unused)) uint8_t irq, uint32_t status)
{
    if(status & DMA_FIFO_ERROR){
        status_reg.dma_fifo_err = true;
    }
    if(status & DMA_DIRECT_MODE_ERROR){
        status_reg.dma_dm_err = true;
    }
    if(status & DMA_TRANSFER_ERROR){
        status_reg.dma_tr_err = true;
    }
    if(status & DMA_HALF_TRANSFER){
        status_reg.dma_hdone = true;
    }
    if(status & DMA_TRANSFER){
        status_reg.dma_done = true;
    }
}


void hash_eodigest_cb(__attribute__((unused)) uint8_t irq, __attribute__((unused)) uint32_t status)
{
}
