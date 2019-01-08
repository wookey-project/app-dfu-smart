/**
 * @file main.c
 *
 * \brief Main of dummy
 *
 */

#include "api/syscall.h"
#include "api/print.h"
#include "libcryp.h"
#include "libtoken_dfu.h"
#include "aes.h"
#include "wookey_ipc.h"
#include "autoconf.h"
#include "main.h"
#include "token.h"
#include "libfw.h"
#include "hash.h"

uint8_t id_pin = 0;

/* Crypto helpers for DFU */
#include "dfu_header.h"

#define SMART_DERIVATION_BECHMARK 0


static volatile bool hash_dma_done = 0;

void hash_dma_cb(uint32_t status __attribute__((unused)))
{
    hash_dma_done = 1;
}

/* cryptographic data */
/* NB: we get back our decrypted signature public key here */
unsigned char decrypted_sig_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
unsigned int decrypted_sig_pub_key_data_len = sizeof(decrypted_sig_pub_key_data);
/* We save our secure channel mounting keys since we want */
unsigned char decrypted_token_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE] = { 0 };
unsigned char decrypted_platform_priv_key_data[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE] = { 0 };
unsigned char decrypted_platform_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE] = { 0 };
databag saved_decrypted_keybag[] = {
    { .data = decrypted_token_pub_key_data, .size = sizeof(decrypted_token_pub_key_data) },
    { .data = decrypted_platform_priv_key_data, .size = sizeof(decrypted_platform_priv_key_data) },
    { .data = decrypted_platform_pub_key_data, .size = sizeof(decrypted_platform_pub_key_data) },
};

static void led_on(void)
{
    /* toggle led ON */
    sys_cfg(CFG_GPIO_SET, (uint8_t)((('C' - 'A') << 4) + 5), 1);
}

static void smartcard_removal_action(void){
    /* Check if smartcard has been removed, and reboot if yes */
    if((dfu_get_token_channel()->card.type != SMARTCARD_UNKNOWN) && !SC_is_smartcard_inserted(&(dfu_get_token_channel()->card))){
        SC_smartcard_lost(&(dfu_get_token_channel()->card));
        sys_reset();
        while(1);
    }
}

/* Current index of chunk treated */
static volatile uint16_t num_chunk = 0;
static int smart_derive_and_inject_key(uint8_t *derived_key, uint32_t derived_key_len, uint16_t num_chunk)
{
    uint8_t iv[16] = { 0 };
    if(derived_key_len != 16){
        goto err;
    }
    if(dfu_token_derive_key_with_error(dfu_get_token_channel(), derived_key, derived_key_len, num_chunk, saved_decrypted_keybag, sizeof(saved_decrypted_keybag)/sizeof(databag))){
        printf("Error during key derivation ...\n");
        set_task_state(DFUSMART_STATE_ERROR);
        goto err;
    }
    /* Now we have to inject the session key into the CRYP device */
    cryp_init_injector(derived_key, KEY_128);
    cryp_init_user(KEY_128, iv, sizeof(iv), AES_CTR, DECRYPT);
    /* We can erase the key now that it has been injected */
    memset(derived_key, 0, derived_key_len);

    return 0;
err:
    memset(derived_key, 0, derived_key_len);
    return 1;
}

/*
 * We use the local -fno-stack-protector flag for main because
 * the stack protection has not been initialized yet.
 *
 * We use _main and not main to permit the usage of exactly *one* arg
 * without compiler complain. argc/argv is not a goot idea in term
 * of size and calculation in a microcontroler
 */
int _main(uint32_t task_id)
{
    /* FIXME: try to make key global, __GLOBAL_OFFSET_TAB error */
    char *wellcome_msg = "hello, I'm smart";
//    char buffer_out[2] = "@@";
    uint8_t id = 0;
    uint8_t id_crypto = 0;
    e_syscall_ret ret = 0;
    logsize_t size = 32;
    int     dma_in_desc, dma_out_desc;

    struct sync_command      ipc_sync_cmd;
    struct sync_command_data ipc_sync_cmd_data;

    // smartcard vars
    int tokenret = 0;
    int dev_desc;

    //

    printf("%s, my id is %x\n", wellcome_msg, task_id);

    ret = sys_init(INIT_GETTASKID, "dfucrypto", &id_crypto);
    printf("crypto is task %x !\n", id_crypto);

    ret = sys_init(INIT_GETTASKID, "pin", &id_pin);
    printf("pin is task %x !\n", id_pin);


    cryp_early_init(false, CRYP_CFG, CRYP_PRODMODE, &dma_in_desc, &dma_out_desc);
    hash_early_init(HASh_TRANS_DMA, HASH_MAP_THROUGH_CRYP, HASH_POLL_MODE);

#if CONFIG_WOOKEY
    // led info
    //
    device_t dev = { 0 };
    strncpy(dev.name, "smart_dfu_led", sizeof("smart_dfu_led"));
    dev.gpio_num = 1;
    dev.gpios[0].mask = GPIO_MASK_SET_MODE | GPIO_MASK_SET_PUPD | GPIO_MASK_SET_SPEED;
    dev.gpios[0].kref.port = GPIO_PC;
    dev.gpios[0].kref.pin = 5;
    dev.gpios[0].pupd = GPIO_NOPULL;
    dev.gpios[0].mode = GPIO_PIN_OUTPUT_MODE;
    dev.gpios[0].speed = GPIO_PIN_HIGH_SPEED;

    ret = sys_init(INIT_DEVACCESS, &dev, &dev_desc);
    if (ret != 0) {
        printf("Error while declaring LED GPIO device: %d\n", ret);
    }
#endif


    tokenret = token_early_init();
    switch (tokenret) {
        case 1:
            printf("error while declaring GPIOs\n");
            break;
        case 2:
            printf("error while declaring USART\n");
            break;
        case 3:
            printf("error while init smartcard\n");
            break;
        default:
            printf("Smartcard early init done\n");
    }

    printf("set init as done\n");
    ret = sys_init(INIT_DONE);
    printf("sys_init returns %s !\n", strerror(ret));

    /*******************************************
     * End of init phase, let's start nominal one
     *******************************************/

#if CONFIG_WOOKEY
    led_on();
#endif
    hash_init(0, hash_dma_cb, HASH_SHA1);

    /*******************************************
     * let's synchronize with other tasks
     *******************************************/
    size = sizeof(struct sync_command);

    /* First, wait for pin to finish its init phase */
    id = id_pin;
    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

    if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_CMD
        && ipc_sync_cmd.state == SYNC_READY) {
        printf("pin has finished its init phase, acknowledge...\n");
    }

    ipc_sync_cmd.magic = MAGIC_TASK_STATE_RESP;
    ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;

    do {
        size = sizeof(struct sync_command);
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);

    /* Then Syncrhonize with crypto */
    size = sizeof(struct sync_command);

    printf("sending end_of_init synchronization to crypto\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    do {
        ret = sys_ipc(IPC_SEND_SYNC, id_crypto, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);

    /* Now wait for Acknowledge from Crypto */
    id = id_crypto;

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
        && ipc_sync_cmd.state == SYNC_ACKNOWLEDGE) {
        printf("crypto has acknowledge end_of_init, continuing\n");
    }

    /* Register smartcard removal handler */
    dfu_get_token_channel()->card.type = SMARTCARD_CONTACT;
    SC_register_user_handler_action(&(dfu_get_token_channel()->card), smartcard_removal_action);
    dfu_get_token_channel()->card.type = SMARTCARD_UNKNOWN;

    /*********************************************
     * Wait for crypto to ask for key injection
     *********************************************/

    id = id_crypto;
    size = sizeof(struct sync_command);
    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (   ipc_sync_cmd.magic == MAGIC_CRYPTO_INJECT_CMD
        && ipc_sync_cmd.state == SYNC_READY) {
        printf("crypto is requesting key injection...\n");
    }

    /*********************************************
     * DFU token communication
     *********************************************/

   /* Token callbacks */
    cb_token_callbacks dfu_token_callbacks = {
        .request_pin                   = dfu_token_request_pin,
        .acknowledge_pin               = dfu_token_acknowledge_pin,
        .request_pet_name              = dfu_token_request_pet_name,
        .request_pet_name_confirmation = dfu_token_request_pet_name_confirmation
    };
    /* this call generates authentication request to PIN */

    if(!tokenret && dfu_token_exchanges(dfu_get_token_channel(), &dfu_token_callbacks, decrypted_sig_pub_key_data, &decrypted_sig_pub_key_data_len, saved_decrypted_keybag, sizeof(saved_decrypted_keybag)/sizeof(databag)))
    {
        goto err;
    }

    printf("cryptography and smartcard initialization done!\n");

    /** Update the error recovery timeout of the channel to 300 milliseconds **/
     dfu_get_token_channel()->error_recovery_sleep = 300;

    /***********************************************
     * Acknowledge key injection to Crypto
     * and send key hash
     ***********************************************/
    ipc_sync_cmd_data.magic = MAGIC_CRYPTO_INJECT_RESP;
    ipc_sync_cmd_data.state = SYNC_DONE;

    do {
      size = sizeof(struct sync_command);
      ret = sys_ipc(IPC_SEND_SYNC, id_crypto, size, (char*)&ipc_sync_cmd_data);
    } while (ret == SYS_E_BUSY);

    // infinite loop at end of init
    printf("Acknowedge send, going back to sleep up keeping only smartcard watchdog.\n");


    /*******************************************
     * Smart main event loop
     *******************************************/
    /* Variables holding the header and the signature of the firmware */
    dfu_update_header_t dfu_header;
    uint8_t sig[EC_MAX_SIGLEN];
    uint8_t tmp_buff[sizeof(dfu_header)+EC_MAX_SIGLEN];
    unsigned char derived_key[16];

    set_task_state(DFUSMART_STATE_IDLE);

    while (1) {
        // detect Smartcard extraction using EXTI IRQ
        id = ANY_APP;
        size = sizeof (struct sync_command_data);

        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
        if (ret != SYS_E_DONE) {
            continue;
        }
	/***************************************************************************/
        if (id == id_crypto) {
            /*******************************
             * Managing Crypto task IPC
             ******************************/
            switch (ipc_sync_cmd_data.magic) {


                case MAGIC_DFU_HEADER_SEND:
                    {
                        if (!is_valid_transition(get_task_state(), MAGIC_DFU_HEADER_SEND)) {
                            goto bad_transition;
                        }

                        set_task_state(DFUSMART_STATE_HEADER);
                        // A DFU header has been received: get it and parse it
#if SMART_DEBUG
                        printf("We have a DFU header IPC, start receiveing\n");
#endif
                        uint32_t tmp_buff_offset = 0;
                        while(ipc_sync_cmd_data.data_size != 0){
                            if((id != id_crypto) || (ipc_sync_cmd_data.magic != MAGIC_DFU_HEADER_SEND)){
#if SMART_DEBUG
                                printf("Error during DFU header receive ...\n");
#endif
                                set_task_state(DFUSMART_STATE_ERROR);
                                goto err;
                            }
                            if(tmp_buff_offset >= sizeof(tmp_buff)){
                                /* We have filled all our buffer, continue to receive without filling */
                                continue;
                            }
                            else if(tmp_buff_offset+ipc_sync_cmd_data.data_size >= sizeof(tmp_buff)){
                                memcpy(tmp_buff+tmp_buff_offset, ipc_sync_cmd_data.data.u8, sizeof(tmp_buff)-tmp_buff_offset);
                                tmp_buff_offset += sizeof(tmp_buff)-tmp_buff_offset;
                            }
                            else{
                                memcpy(tmp_buff+tmp_buff_offset, ipc_sync_cmd_data.data.u8, ipc_sync_cmd_data.data_size);
                                tmp_buff_offset += ipc_sync_cmd_data.data_size;
                            }
                            size = sizeof (struct sync_command_data);
                            ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
                            if (ret != SYS_E_DONE) {
                                continue;
                            }
                        }

                        set_task_state(DFUSMART_STATE_AUTH);

                        if(dfu_parse_header(tmp_buff, sizeof(tmp_buff), &dfu_header, sig, sizeof(sig))){
#if SMART_DEBUG
                            printf("Error: bad header received from USB through crypto!\n");
#endif
                            set_task_state(DFUSMART_STATE_ERROR);
                            ipc_sync_cmd.magic = MAGIC_DFU_HEADER_INVALID;
                            ipc_sync_cmd.state = SYNC_DONE;
                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

                            continue;

                        }

#if SMART_DEBUG
                        dfu_print_header(&dfu_header);
#endif
#if 0
                        /* now let's ask the user for validation */
                        ipc_sync_cmd_data.magic = MAGIC_DFU_HEADER_SEND;
                        ipc_sync_cmd_data.state = SYNC_DONE;
                        /* FIXME: the fields that need to be user-validated are still to be selected */
                        ipc_sync_cmd_data.data.u32[0] = dfu_header.magic;
                        ipc_sync_cmd_data.data.u32[1] = dfu_header.version;
                        ipc_sync_cmd_data.data_size = 2;
                        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

                        /* Now wait for Acknowledge from pin */
                        id = id_pin;
                        size = sizeof(struct sync_command_data); /* max pin size: 32 */

                        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
                        printf("received (in)validation from PIN\n");
                        if (ipc_sync_cmd_data.magic == MAGIC_DFU_HEADER_INVALID) {
                            /* Pin said it is invalid, returning invalid to DFU and break the download management */
                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
                            continue;
                        }
                        if (ipc_sync_cmd_data.magic == MAGIC_DFU_HEADER_VALID) {
                            /* Pin said it is valid */
                            printf("Validation from Pin. continuing.\n");
                        }
                        /* PIN said it is okay, continuing */
#endif
                        /* before starting cryptographic session, let's check
                         * that this is the good file (i.e. flip for flop mode
                         * and flop for flip mode */


                        if ((is_in_flip_mode() && dfu_header.type == FLIP) ||
                            (is_in_flop_mode() && dfu_header.type == FLOP)   ) {
                            printf("invalid file: trying to erase current bank \n");
                            set_task_state(DFUSMART_STATE_ERROR);
                            ipc_sync_cmd.magic = MAGIC_DFU_HEADER_INVALID;
                            ipc_sync_cmd.state = SYNC_BADFILE;
                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
                            /* returning back to IDLE */
                            set_task_state(DFUSMART_STATE_IDLE);
                            continue;
                        }

                        /* Now that we have the header, let's begin our decrypt session */
                        if(dfu_token_begin_decrypt_session_with_error(dfu_get_token_channel(), tmp_buff, sizeof(dfu_header)+dfu_header.siglen, saved_decrypted_keybag, sizeof(saved_decrypted_keybag)/sizeof(databag))) {
#if SMART_DEBUG
                            printf("Error: dfu_token_begin_decrypt_session returned an error!");
#endif
                            goto err;
                        }
			num_chunk = 0;

                        ret = smart_derive_and_inject_key(derived_key, sizeof(derived_key), num_chunk);
                        if (ret) {
#if SMART_DEBUG
                            printf("Error: dfu_token_derive_key returned an error!");
#endif
                            goto err;
                        }
			num_chunk++;
                        /* sending back acknowledge to DFUUSB */
                        memset((void*)&ipc_sync_cmd_data, 0, sizeof(struct sync_command_data));
                        ipc_sync_cmd_data.magic = MAGIC_DFU_HEADER_VALID;
                        ipc_sync_cmd_data.state = SYNC_DONE;
                        ipc_sync_cmd_data.data.u16[0] = dfu_header.chunksize;
                        ipc_sync_cmd_data.data_size = 1;
                        sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

                        set_task_state(DFUSMART_STATE_DWNLOAD);

                        break;
                    }


                /********* Key injection request *************/
                case MAGIC_CRYPTO_INJECT_CMD:
                    {

                        if (!is_valid_transition(get_task_state(), MAGIC_CRYPTO_INJECT_CMD)) {
                            goto bad_transition;
                        }

                        /* do we have to reinject the key ? only write mode request crypto.
                         * Each chunk we need to derivate the IV and update it in the CRYP device in
                         * order to uncypher correctly the next one (using the correct IV).
                         */

                        ret = smart_derive_and_inject_key(derived_key, sizeof(derived_key), num_chunk);
                        if (ret) {
                            ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_RESP;
                            ipc_sync_cmd.state = SYNC_FAILURE;

                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
                            set_task_state(DFUSMART_STATE_ERROR);
                            continue;
                        }
			num_chunk++;
                        // FIXME To add
                        // A DFU chunk has been received. chunk id is passed
                        // in the received IPC

                        /* acknowledge the IV update to crypto */
                        ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_RESP;
                        ipc_sync_cmd.state = SYNC_DONE;

                        sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
                        break;
                    }

                case MAGIC_DFU_WRITE_FINISHED:
                    {

                        if (!is_valid_transition(get_task_state(), MAGIC_DFU_WRITE_FINISHED)) {
                            goto bad_transition;
                        }
                        set_task_state(DFUSMART_STATE_CHECKSIG);
                        printf("checking signature of firmware\n");
                        break;
                    }
                    /********* defaulting to none    *************/
                default:
                    {
                        break;
                    }
            }
        }

	/***************************************************************************/
        if (id == id_pin) {
            /*******************************
             * Managing Pin task IPC
             ******************************/
            switch (ipc_sync_cmd_data.magic) {

                /********* set user pin into smartcard *******/
                case MAGIC_SETTINGS_CMD:
                    {

                        if (!is_valid_transition(get_task_state(), MAGIC_SETTINGS_CMD)) {
                            goto bad_transition;
                        }
                        /*
                        if (channel_state != CHAN_UNLOCKED) {
                          printf("channel has not been unlocked. You must authenticate yourself first\n");
                          continue;
                        }
                         */
                        if (   ipc_sync_cmd_data.data.req.sc_type == SC_PET_PIN
                            && ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY) {
                            /* set the new pet pin. The CRYPTO_DFU_CMD must have been passed and the channel being unlocked */
                            printf("PIN require a Pet Pin update\n");

                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_PET_PIN };
                            if(dfu_token_unlock_ops_exec(dfu_get_token_channel(), ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0, NULL, 0)){
                                printf("Unable to change pet pin!!!\n");
                                continue;
                            }
                            printf("New pet pin registered\n");
                        } else if (   ipc_sync_cmd_data.data.req.sc_type == SC_USER_PIN
                                   && ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY) {
                            /* set the new pet pin. The CRYPTO_DFU_CMD must have been passed and the channel being unlocked */
                            printf("PIN require a User Pin update\n");

                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_USER_PIN };
                            if(dfu_token_unlock_ops_exec(dfu_get_token_channel(), ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0, NULL, 0)){
                                printf("Unable to change user pin!!!\n");
                                continue;
                            }
                            printf("New user pin registered\n");
                        } else if (   ipc_sync_cmd_data.data.req.sc_type == SC_PET_NAME
                                   && ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY) {
                            /* set the new pet pin. The CRYPTO_DFU_CMD must have been passed and the channel being unlocked */
                            printf("PIN require a Pet Name update\n");
                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_PET_NAME };
                            if(dfu_token_unlock_ops_exec(dfu_get_token_channel(), ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0, NULL, 0)){
                                printf("Unable to change pet name!!!\n");
                                continue;
                            }
                            printf("New pet name registered\n");
                        } else {
                            printf("Invalid PIN command bag : sc_type = %d, sc_req = %d!\n",
                                    ipc_sync_cmd_data.data.req.sc_type,
                                    ipc_sync_cmd_data.data.req.sc_req);
                        }
                        break;
                    }

                /********* lock the device (by rebooting) ***/
                case MAGIC_SETTINGS_LOCK:
                    {

                        if (!is_valid_transition(get_task_state(), MAGIC_SETTINGS_LOCK)) {
                            goto bad_transition;
                        }
                        sys_reset();
                        while (1);
                        break;
                    }




                    /********* defaulting to none    *************/
                default:
                    {
                        printf("unknown request !!!\n");
                        // FIXME: to be added: goto bad_transition;
                        break;
                    }
            }

        }

        // nothing ? just wait for next event
        sys_yield();
    }


    return 0;

bad_transition:
    printf("invalid transition from state %d, magic %x\n", get_task_state(),
            ipc_sync_cmd_data.magic);
    set_task_state(DFUSMART_STATE_ERROR);
err:
    printf("Oops\n");
    sys_reset();
    while(1);
    return 0;
}
