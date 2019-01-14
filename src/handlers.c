#include "api/print.h"
#include "api/types.h"
#include "api/syscall.h"
#include "main.h"

volatile status_reg_t status_reg = { 0 }; 

void hash_dma_cb(uint8_t irq, uint32_t status)
{
    irq = irq;
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


void hash_eodigest_cb(uint8_t irq, uint32_t status)
{
    irq = irq;
    status = status;
}
