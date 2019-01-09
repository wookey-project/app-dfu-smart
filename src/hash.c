#include "hash.h"
#include "hash_regs.h"
#include "api/syscall.h"
#include "api/print.h"
#include "api/string.h"
#include "api/regutils.h"

enum dma_controller {
    DMA1 = 1,
    DMA2 = 2
};


#define DMA2_STREAM_HASH_IN 7
#define DMA2_CHANNEL_HASH_IN 2


static bool use_dma = false;
static bool use_it  = false;

static int dma_hash_desc = 0;
static int dev_hash_desc = 0;
static dma_t dma_hash = { 0 };
static device_t dev_hash = { 0 };

static cb_endofdigest eodigest_cb = 0;
static cb_endofdma    eodma_cb = 0;

static void hash_send_buf_dma(physaddr_t buff, uint32_t size)
{
    uint8_t ret;

    dma_hash.in_addr = buff;
    dma_hash.size    = size;

    ret = sys_cfg(CFG_DMA_RECONF, &dma_hash,
                  (DMA_RECONF_BUFIN | DMA_RECONF_BUFOUT | DMA_RECONF_BUFSIZE),
                   dma_hash_desc);

    if (ret != SYS_E_DONE) {
        printf("Enable to launch DMA!\n");
    }
}

static void hash_send_buf_nodma(physaddr_t buff, uint32_t size)
{
    uint32_t *tab = (uint32_t*)buff;
    /* buff is naturally trunkated to a multiple of 4 bytes here */
    for (uint32_t offset = 0; offset < size / 4; ++offset) {
        write_reg_value(_r_CORTEX_M_HASH_DIN, tab[offset]);
    }
    /* residual ? size not a multiple of 4 ? */
}


static void dma_hash_handler(uint8_t irq __attribute__((unused)),
                             uint32_t status)
{
    if (eodma_cb) {
        eodma_cb(status);
    }

}

static void hash_handler(uint8_t irq __attribute__((unused)),
                         uint32_t status,
                         uint32_t data __attribute__((unused)))
{
    /* executing the user callback at ISR time when DCIE interrupt rise */
    if (eodigest_cb) {
        eodigest_cb(status);
    }
}

uint8_t hash_finalize(void)
{
    return 0;
}

uint8_t hash_request(hash_req_type_t      type,
                     uint32_t             addr,
                     uint32_t             size)
{
    /* if size is not 512 multiple, setting DCAL to 1 automatically
     * pad to finish the last chunk calculation if needed and the
     * result is calculated */
    if (type == HASH_REQ_LAST) {
        /* last request */
        if (!use_dma) {
            hash_send_buf_nodma(addr, size);
            set_reg(_r_CORTEX_M_HASH_STR, 0x1, HASH_STR_DCAL);
        } else {
            set_reg(_r_CORTEX_M_HASH_CR, 0x0, HASH_CR_MDMAT);
            hash_send_buf_dma(addr, size);
            set_reg(_r_CORTEX_M_HASH_STR, 0x1, HASH_STR_DCAL);
        }
    } else {
        if (use_dma) {
            set_reg(_r_CORTEX_M_HASH_CR, 0x1, HASH_CR_MDMAT);
            hash_send_buf_dma(addr, size);
        } else {
            hash_send_buf_nodma(addr, size);
        }
    }
    return 0;
}

uint8_t hash_init(cb_endofdigest eodigest_callback,
                  cb_endofdma    eodma_callback,
                  hash_algo_t algo)
{
    uint32_t reg = 0;
    /* registering the End Of Digest callback */
    if (eodigest_callback) {
        eodigest_cb = eodigest_callback;
    }
    if (eodma_callback) {
        eodma_cb = eodma_callback;
    }

    /* configure the HASH device, depending on the choosen configuration */

    /* datatype mode (bit-swapping, depending on the input data type, see
     * STM-RM0090 chap 25.3.2 */
    /* byte-based little to big translation */
    set_reg(&reg, 2, HASH_CR_DATATYPE);

    switch (algo) {
        case HASH_SHA1:
            /* algo[0:1] == 0 */
            break;
        case HASH_MD5:
            set_reg(&reg, 1, HASH_CR_ALGO0);
            break;
        case HASH_SHA224:
            set_reg(&reg, 1, HASH_CR_ALGO1);
            break;
        case HASH_SHA256:
            set_reg(&reg, 1, HASH_CR_ALGO0);
            set_reg(&reg, 1, HASH_CR_ALGO1);
            break;
        case HASH_HMAC_SHA1:
            set_reg(&reg, 1, HASH_CR_MODE);
            printf("hmac procedure not yet supported. Stopping init here\n");
            goto err;
            break;
        case HASH_HMAC_SHA224:
            set_reg(&reg, 1, HASH_CR_ALGO1);
            set_reg(&reg, 1, HASH_CR_MODE);
            printf("hmac procedure not yet supported. Stopping init here\n");
            goto err;
            break;
        case HASH_HMAC_SHA256:
            set_reg(&reg, 1, HASH_CR_ALGO0);
            set_reg(&reg, 1, HASH_CR_ALGO1);
            set_reg(&reg, 1, HASH_CR_MODE);
            printf("hmac procedure not yet supported. Stopping init here\n");
            goto err;
            break;
        default:
            printf("unsupported hash algorithm!\n");
            goto err;
    }
    if (use_dma) {
        set_reg(&reg, 1, HASH_CR_DMAE);
    }

    /* setting CR with all configured fields */
    write_reg_value(_r_CORTEX_M_HASH_CR, reg);


    /* let's configure the interrupts */
    if (use_it) {
        set_reg(_r_CORTEX_M_HASH_IMR, 1, HASH_IMR_DCIE);
    }

    /* end of init, activating HASH */
    set_reg(_r_CORTEX_M_HASH_CR, 0x1, HASH_CR_INIT);

    return 0;
err:
    return 1;
}

uint8_t hash_early_init(hash_transfert_mode_t transfert_mode,
                        hash_map_mode_t       map_mode,
                        hash_dev_mode_t       dev_mode)
{
    e_syscall_ret ret;

    if (transfert_mode != HASH_TRANS_NODMA) {

        dma_hash.dma          = DMA2;
        dma_hash.stream       = DMA2_STREAM_HASH_IN;
        dma_hash.channel      = DMA2_CHANNEL_HASH_IN;
        dma_hash.dir          = MEMORY_TO_PERIPHERAL;
        dma_hash.in_addr      = (physaddr_t) 0;
        dma_hash.out_addr     = (volatile physaddr_t)_r_CORTEX_M_HASH_DIN;
        dma_hash.in_prio      = DMA_PRI_MEDIUM;
        dma_hash.size         = 0;
        dma_hash.mode         = DMA_DIRECT_MODE;
        dma_hash.mem_inc      = 1;
        dma_hash.dev_inc      = 0;
        dma_hash.datasize     = DMA_DS_WORD;
        dma_hash.mem_burst    = DMA_BURST_INC4;
        dma_hash.dev_burst    = DMA_BURST_INC4;
        dma_hash.flow_control = DMA_FLOWCTRL_DMA;
        dma_hash.in_handler   = (user_dma_handler_t) dma_hash_handler;
        dma_hash.out_handler  = (user_dma_handler_t) 0;    /* not used */

#ifdef CONFIG_USR_DRV_HASH_DEBUG
        printf("init DMA CRYP in...\n");
#endif

        // FIXME - handling ret value
        ret = sys_init(INIT_DMA, &dma_hash, &dma_hash_desc);
        if (ret != SYS_E_DONE) {
            goto err;
        }

        use_dma = true;
    }

    switch (map_mode) {
        case HASH_MAP_THROUGH_CRYP:
            {
    /* if HASH is mapped through CRYP, we consider that the task is
     * using the cryp driver in cryp-full or cryp-cfg mode, which include,
     * in both cases, the cryp *and* the hash device. This means that
     * this driver doesn't need to map the hash device in memory.
     * If the hash driver is standalone (without using the cryp driver)
     * the hash device is mapped here */
                printf("hash device already mapped by cryp driver\n");
                printf("be sure that cryp_init() has been called before\n");
                break;
            }
        case HASH_MAP_STANDALONE:
        case HASH_MAP_STANDALONE_VOLUNTARY:
            {
                printf("decaring hash device\n");
                const char *name = "hash";
                memset((void*)&dev_hash, 0, sizeof(device_t));
                strncpy(dev_hash.name, name, sizeof (dev_hash.name));
                dev_hash.address = 0x50060400;
                dev_hash.size = 0x400;
                if (map_mode == HASH_MAP_STANDALONE) {
                    dev_hash.map_mode = DEV_MAP_AUTO;
                } else {
                    dev_hash.map_mode = DEV_MAP_VOLUNTARY;
                }
                if (dev_mode == HASH_IT_DIGEST_COMPLETE) {
                    dev_hash.irq_num = 1;
                    dev_hash.irqs[0].handler = hash_handler;
                    dev_hash.irqs[0].irq = HASH_IRQ;
                    dev_hash.irqs[0].mode = IRQ_ISR_STANDARD;
                    /* SR register*/
                    dev_hash.irqs[0].posthook.status = 0x00024;
                    dev_hash.irqs[0].posthook.data   = 0;
                    /* read SR */
                    dev_hash.irqs[0].posthook.action[0].instr = IRQ_PH_READ;
                    dev_hash.irqs[0].posthook.action[0].read.offset = 0x0024;
                    /* clear Digest complete status */
                    dev_hash.irqs[0].posthook.action[2].instr = IRQ_PH_WRITE;
                    dev_hash.irqs[0].posthook.action[2].write.offset = 0x0024;
                    dev_hash.irqs[0].posthook.action[2].write.value  = 0x0;
                    dev_hash.irqs[0].posthook.action[2].write.mask   = HASH_SR_DCIS_Msk;
                    use_it = true;
                } else {
                    dev_hash.irq_num = 0;
                }
                dev_hash.gpio_num = 0;
                ret = sys_init(INIT_DEVACCESS, &dev_hash, &dev_hash_desc);
                if (ret != SYS_E_DONE) {
                    goto err;
                }
            }
        default:
            {
                printf("invalid map mode !\n");
                goto err;
            }
    }

#ifdef CONFIG_USR_DRV_HASH_DEBUG
    printf("sys_init returns %s !\n", strerror(ret));
#endif
    return 0;
err:
    return 1;
}
