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
#include "libhash.h"
#include "handlers.h"
#include "api/types.h"

uint8_t id_pin = 0;

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
/* Maximum number of chunks we have to handle */
static volatile uint16_t max_num_chunk = 0;
static int smart_derive_and_inject_key(uint8_t *derived_key, uint32_t derived_key_len, uint16_t num_chunk)
{
    if(derived_key_len != 16){
        goto err;
    }
    /* Sanity check: we should not overflow the maximum chunk number */
    if(num_chunk > max_num_chunk){
#if SMART_DEBUG
        printf("Error during key derivation ... asked chunk number %d exceeds max chunk number %d\n", num_chunk, max_num_chunk);
#endif
        goto err;
    }
    if(dfu_token_derive_key_with_error(dfu_get_token_channel(), derived_key, derived_key_len, num_chunk, saved_decrypted_keybag, sizeof(saved_decrypted_keybag)/sizeof(databag))){
#if SMART_DEBUG
        printf("Error during key derivation ... dfu_token_derive_key_with_error\n");
#endif
        set_task_state(DFUSMART_STATE_ERROR);
        goto err;
    }
    /* Now we have to inject the session key into the CRYP device */
    cryp_init_injector(derived_key, KEY_128);
    /* We can erase the key now that it has been injected */
    memset(derived_key, 0, derived_key_len);

    return 0;
err:
    memset(derived_key, 0, derived_key_len);
    return 1;
}

void init_flash_map(void)
{
    if (is_in_flip_mode()) {
        t_device_mapping devmap = {
#ifdef CONFIG_WOOKEY
            .map_flip_shr = 1,
            .map_flip = 0,
# if CONFIG_FIRMWARE_DUALBANK
            .map_flop_shr = 1,
# else
            .map_flop_shr = 0,
# endif
            .map_flop = 0,
#else
# if CONFIG_USR_DRV_FLASH_DUAL_BANK
            .map_mem_bank1 = 0,
            .map_mem_bank2 = 0,
# else
            .map_mem = 0,
# endif
#endif
            .map_ctrl = 0,
#ifdef CONFIG_WOOKEY
            .map_ctrl_2 = 1,
#endif
            .map_system = 0,
            .map_otp = 0,
            .map_opt_bank1 = 0,
#if CONFIG_USR_DRV_FLASH_DUAL_BANK
            .map_opt_bank2 = 0,
#endif
        };
        // mapping flop
        firmware_early_init(&devmap);
    } else if (is_in_flop_mode()) {
        // mapping flip
        t_device_mapping devmap = {
#ifdef CONFIG_WOOKEY
            .map_flip_shr = 1,
            .map_flip = 0,
# if CONFIG_FIRMWARE_DUALBANK
            .map_flop_shr = 1,
# else
            .map_flop_shr = 0,
# endif
            .map_flop = 0,
#else
# if CONFIG_USR_DRV_FLASH_DUAL_BANK
            .map_mem_bank1 = 0,
            .map_mem_bank2 = 0,
# else
            .map_mem = 0,
# endif
#endif
            .map_ctrl = 0,
#ifdef CONFIG_WOOKEY
            .map_ctrl_2 = 1,
#endif
            .map_system = 0,
            .map_otp = 0,
            .map_opt_bank1 = 0,
#if CONFIG_USR_DRV_FLASH_DUAL_BANK
            .map_opt_bank2 = 0,
#endif
        };
        firmware_early_init(&devmap);
    }
}


#ifdef __GNUC__
#ifdef __clang__
# pragma clang optimize off
#else
# pragma GCC push_options
# pragma GCC optimize("O0")
#endif
#endif
static secbool check_signature(const firmware_header_t *dfu_header, const uint8_t firmware_sig[EC_MAX_SIGLEN], const uint8_t *digest, uint32_t sizeofdigest){
	uint8_t siglen;
	const ec_str_params *the_curve_const_parameters;
	ec_params curve_params;
	struct ec_verify_context verif_ctx, verif_ctx_double_check;
	ec_pub_key sig_pub_key;

	if((digest == NULL) || (firmware_sig == NULL)){
		goto err;
	}
	/* Check the signature */
	/* Map the curve parameters to our libecc internal representation */
        the_curve_const_parameters = ec_get_curve_params_by_type(dfu_get_token_channel()->curve);
        import_params(&curve_params, the_curve_const_parameters);
        if(ec_get_sig_len(&curve_params, ECDSA, SHA256, &siglen)){
#if SMART_DEBUG
		printf("Error: ec_get_sig_len error\n");
#endif
		goto err;
	}
	if(dfu_header->siglen != siglen){
		/* Sanity check on the signature length we got from the header, and the one we compute */
#if SMART_DEBUG
		printf("Error: dfu_header.siglen (%d) != siglen (%d)\n", dfu_header->siglen, siglen);
#endif
		goto err;
	}
	if(ec_structured_pub_key_import_from_buf(&sig_pub_key, &curve_params, decrypted_sig_pub_key_data, decrypted_sig_pub_key_data_len, ECDSA)){
#if SMART_DEBUG
		printf("Error: ec_structured_pub_key_import_from_buf\n");
#endif
		goto err;
	}

	/* Verify the signature with double check (against faults) */
	int ec_ret1 = 0x55aa55aa, ec_ret2 = 0xaa55aa55;
	int ec_ret1_ = 0xaa55aa55, ec_ret2_ = 0x55aa55aa;
	if(ec_verify_init(&verif_ctx, &sig_pub_key, firmware_sig, siglen, ECDSA, SHA256)){
#if SMART_DEBUG
		printf("Error: ec_verify_init\n");
#endif
		goto err;
	}
	if(ec_verify_init(&verif_ctx_double_check, &sig_pub_key, firmware_sig, siglen, ECDSA, SHA256)){
#if SMART_DEBUG
		printf("Error: ec_verify_init\n");
#endif
		goto err;
	}
	if(ec_verify_update(&verif_ctx, digest, sizeofdigest)){
#if SMART_DEBUG
		printf("Error: ec_verify_update\n");
#endif
		goto err;
	}
	if(ec_verify_update(&verif_ctx_double_check, digest, sizeofdigest)){
#if SMART_DEBUG
		printf("Error: ec_verify_update\n");
#endif
		goto err;
	}
	ec_ret1 = ec_verify_finalize(&verif_ctx);
	ec_ret2 = ec_verify_finalize(&verif_ctx_double_check);
	ec_ret1_ = ec_ret1;
	ec_ret2_ = ec_ret2;
	if(ec_ret1 || ec_ret2){
#if SMART_DEBUG
		printf("Error: ec_verify_finalize, signature not OK\n");
#endif
		goto err;
	}
	if(ec_ret2_ || ec_ret1_){
#if SMART_DEBUG
		printf("Error: ec_verify_finalize, signature not OK\n");
#endif
		goto err;
	}

	return sectrue;

err:
	return secfalse;
}

static secbool check_antirollback(const firmware_header_t *dfu_header){

	if(dfu_header == NULL){
		goto err;
	}
	/* Make the anti-rollback check a little more robust against
	 * faults.
	 */
        uint32_t version = fw_get_current_version(FW_VERSION_FIELD_ALL);
        uint32_t version_doublecheck = fw_get_current_version(FW_VERSION_FIELD_ALL);
        if (dfu_header->version <= version) {
#if SMART_DEBUG
            printf("rollback alert!\n");
#endif
            goto err;
        }
        if (dfu_header->version <= version_doublecheck){
            /* Fault */
            goto err;
	}
	if(version != version_doublecheck){
            /* Fault */
            goto err;
	}
	/* Better safe than sorry ... Second attempt */
	version = fw_get_current_version(FW_VERSION_FIELD_ALL);
        version_doublecheck = fw_get_current_version(FW_VERSION_FIELD_ALL);
        if (dfu_header->version <= version) {
#if SMART_DEBUG
            printf("rollback alert!\n");
#endif
            goto err;
        }
        if (dfu_header->version <= version_doublecheck){
            /* Fault */
            goto err;
	}
	if(version != version_doublecheck){
            /* Fault */
            goto err;
	}
#if SMART_DEBUG
        printf("cur version: %x, req: %x\n", dfu_header->version, version);
#endif
	return sectrue;

err:
	return secfalse;
}
#ifdef __GNUC__
#ifdef __clang__
# pragma clang optimize on
#else
# pragma GCC pop_options
#endif
#endif

/*
 * We use the local -fno-stack-protector flag for main because
 * the stack protection has not been initialized yet.
 *
 * We use _main and not main to permit the usage of exactly *one* arg
 * without compiler complain. argc/argv is not a goot idea in term
 * of size and calculation in a microcontroler
 */
#if SMART_DEBUG
int _main(uint32_t task_id)
#else
int _main(__attribute__((unused)) uint32_t task_id)
#endif
{
    /* FIXME: try to make key global, __GLOBAL_OFFSET_TAB error */
#if SMART_DEBUG
    char *wellcome_msg = "hello, I'm smart";
#endif
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

#if SMART_DEBUG
    printf("%s, my id is %x\n", wellcome_msg, task_id);
#endif

    ret = sys_init(INIT_GETTASKID, "dfucrypto", &id_crypto);
#if SMART_DEBUG
    printf("crypto is task %x !\n", id_crypto);
#endif

    ret = sys_init(INIT_GETTASKID, "pin", &id_pin);
#if SMART_DEBUG
    printf("pin is task %x !\n", id_pin);
#endif


    cryp_early_init(false, CRYP_MAP_VOLUNTARY, CRYP_CFG, CRYP_PRODMODE, &dma_in_desc, &dma_out_desc);
    hash_early_init(HASh_TRANS_DMA, HASH_MAP_VOLUNTARY, HASH_POLL_MODE);

#if CONFIG_WOOKEY
    // led info
    //
    device_t dev;
    memset(&dev, 0, sizeof(device_t));
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
#if SMART_DEBUG
        printf("Error while declaring LED GPIO device: %d\n", ret);
#endif
	goto err;
    }
#endif

    init_flash_map();

    tokenret = token_early_init(TOKEN_MAP_VOLUNTARY);
    switch (tokenret) {
        case 1:
#if SMART_DEBUG
            printf("error while declaring GPIOs\n");
#endif
            goto err;
        case 2:
#if SMART_DEBUG
            printf("error while declaring USART\n");
#endif
            goto err;
        case 3:
#if SMART_DEBUG
            printf("error while init smartcard\n");
#endif
            goto err;
        default:
#if SMART_DEBUG
            printf("Smartcard early init done\n");
#endif
            break;
    }

#if SMART_DEBUG
    printf("set init as done\n");
#endif
    ret = sys_init(INIT_DONE);
#if SMART_DEBUG
    printf("sys_init returns %s !\n", strerror(ret));
#endif
    /*******************************************
     * End of init phase, let's start nominal one
     *******************************************/

#if CONFIG_WOOKEY
    led_on();
#endif
    if(hash_unmap()){
         goto err;
    }
    if (token_map()) {
         goto err;
    }

    /*******************************************
     * let's synchronize with other tasks
     *******************************************/
    size = sizeof(struct sync_command);

    /* First, wait for pin to finish its init phase */
    id = id_pin;
    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

    if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_CMD
        && ipc_sync_cmd.state == SYNC_READY) {
#if SMART_DEBUG
        printf("pin has finished its init phase, acknowledge...\n");
#endif
    }

    ipc_sync_cmd.magic = MAGIC_TASK_STATE_RESP;
    ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;

    do {
        size = sizeof(struct sync_command);
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);

    /* Then Syncrhonize with crypto */
    size = sizeof(struct sync_command);

#if SMART_DEBUG
    printf("sending end_of_init synchronization to crypto\n");
#endif
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
#if SMART_DEBUG
        printf("crypto has acknowledge end_of_init, continuing\n");
#endif
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
#if SMART_DEBUG
        printf("crypto is requesting key injection...\n");
#endif
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

#if SMART_DEBUG
    printf("cryptography and smartcard initialization done!\n");
#endif

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
#if SMART_DEBUG
    printf("Acknowedge send, going back to sleep up keeping only smartcard watchdog.\n");
#endif


    /*******************************************
     * Smart main event loop
     *******************************************/
    /* Variables holding the header and the signature of the firmware */
    firmware_header_t dfu_header;
    uint8_t firmware_sig[EC_MAX_SIGLEN];
    /* NOTE: alignment due to DMA */
    __attribute__((aligned(4))) uint8_t tmp_buff[sizeof(dfu_header)+EC_MAX_SIGLEN];
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
                        if (is_valid_transition(get_task_state(), MAGIC_DFU_HEADER_SEND) != sectrue) {
                            goto bad_transition;
                        }

                        set_task_state(DFUSMART_STATE_HEADER);
                        ipc_sync_cmd.magic = MAGIC_DFU_DWNLOAD_STARTED;
                        ipc_sync_cmd.state = SYNC_DONE;
                        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

                        /* we send to pin the information that the DFU as started */
                        // A DFU header has been received: get it and parse it
#if SMART_DEBUG
                        printf("We have a DFU header IPC, start receiving\n");
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

                        if(firmware_parse_header(tmp_buff, sizeof(tmp_buff), sizeof(firmware_sig), &dfu_header, firmware_sig)){
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
                        firmware_print_header(&dfu_header);
#endif
                        if (token_unmap()) {
#if SMART_DEBUG
                            printf("Unable to map token!\n");
#endif
                            goto err;
                        }

                        /* rollback check (version comparison with current) */
			if(check_antirollback(&dfu_header) != sectrue){
				goto err;
			}
		        if (token_map()) {
#if SMART_DEBUG
		             printf("Unable to map token!\n");
#endif
		            goto err;
		        }
		        if (cryp_map()) {
#if SMART_DEBUG
		             printf("Unable to map token!\n");
#endif
		            goto err;
		        }


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
#if SMART_DEBUG
                        printf("received (in)validation from PIN\n");
#endif
                        if (ipc_sync_cmd_data.magic == MAGIC_DFU_HEADER_INVALID) {
                            /* Pin said it is invalid, returning invalid to DFU and break the download management */
                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
                            continue;
                        }
                        if (ipc_sync_cmd_data.magic == MAGIC_DFU_HEADER_VALID) {
                            /* Pin said it is valid */
#if SMART_DEBUG
                            printf("Validation from Pin. continuing.\n");
#endif
                        }
                        /* PIN said it is okay, continuing */
                        /* before starting cryptographic session, let's check
                         * that this is the good file (i.e. flip for flop mode
                         * and flop for flip mode */
#if 0
                        if (cryp_unmap()) {
                            printf("Unable to unmap cryp!\n");
                            goto err;
                        }
                        if (token_unmap()) {
                            printf("Unable to unmap token!\n");
                            goto err;
                        }
                        clear_other_header();
                        if (token_map()) {
                            printf("Unable to map token!\n");
                            goto err;
                        }
                        if (cryp_map()) {
                            printf("Unable to map cryp!\n");
                            goto err;
                        }
#endif


                        if ((is_in_flip_mode() && (firmware_is_partition_flip(&dfu_header) == true)) ||
                            (is_in_flop_mode() && (firmware_is_partition_flop(&dfu_header) == true))  ) {
#if SMART_DEBUG
                            printf("invalid file: trying to erase current bank \n");
#endif
                            set_task_state(DFUSMART_STATE_ERROR);
                            ipc_sync_cmd.magic = MAGIC_DFU_HEADER_INVALID;
                            ipc_sync_cmd.state = SYNC_BADFILE;
                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
                            /* returning back to IDLE */
                            set_task_state(DFUSMART_STATE_IDLE);
                            continue;
                        }
			/* Sanity check on the size */
                        if ((is_in_flip_mode() && (dfu_header.len > firmware_get_flop_size())) ||
                            (is_in_flop_mode() && (dfu_header.len > firmware_get_flip_size()))  ) {
#if SMART_DEBUG
                            printf("invalid size %d from header overflows partition size\n", dfu_header.len);
#endif
                            set_task_state(DFUSMART_STATE_ERROR);
                            ipc_sync_cmd.magic = MAGIC_DFU_HEADER_INVALID;
                            ipc_sync_cmd.state = SYNC_BADFILE;
                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
                            /* returning back to IDLE */
                            set_task_state(DFUSMART_STATE_IDLE);
                            continue;
                        }
                        /* Compute the number of crypto chunks we have from the header */
                        max_num_chunk = dfu_header.len / dfu_header.chunksize;
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

                        if (is_valid_transition(get_task_state(), MAGIC_CRYPTO_INJECT_CMD) != sectrue) {
                            goto bad_transition;
                        }

                        /* do we have to reinject the key ? only write mode request crypto.
                         * Each chunk we need to derivate the key and update it in the CRYP device.
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
			if(cryp_unmap()){
				goto err;
			}
			if(hash_map()){
				goto err;
			}
			/* When we enter the CHECKSIG state, nothing should make us change our state except an error */
                        if (is_valid_transition(get_task_state(), MAGIC_DFU_WRITE_FINISHED) != sectrue) {
                            goto bad_transition;
                        }
                        set_task_state(DFUSMART_STATE_CHECKSIG);
#if SMART_DEBUG
                        printf("checking signature of firmware\n");
#endif
			/* FIXME: to be moved to the lib firmware for more readability */
    			hash_init(hash_eodigest_cb, hash_dma_cb, HASH_SHA256);
			/* Begin to hash the header */
                if(firmware_header_to_raw(&dfu_header, tmp_buff, sizeof(tmp_buff))){
                    goto err;
                }
                status_reg.dma_fifo_err = status_reg.dma_dm_err = status_reg.dma_tr_err = false;
                status_reg.dma_done = false;
                /* Sanity check */
                if(sizeof(dfu_header) < (FW_IV_LEN+FW_HMAC_LEN)){
                    goto err;
                }
                hash_request(HASH_REQ_IN_PROGRESS, (uint32_t)&tmp_buff, sizeof(dfu_header)-FW_IV_LEN-FW_HMAC_LEN);
                while (status_reg.dma_done == false){
                    bool dma_error = status_reg.dma_fifo_err || status_reg.dma_dm_err || status_reg.dma_tr_err;
                    if(dma_error == true){
                        /* We had a DMA error ... Get out */
                        goto err;
                    }
                }
                status_reg.dma_fifo_err = status_reg.dma_dm_err = status_reg.dma_tr_err = false;
                        status_reg.dma_done = false;
                        if (is_in_flip_mode()) {
                            hash_request(HASH_REQ_LAST, firmware_get_flop_base_addr(), dfu_header.len);
                        } else if (is_in_flop_mode()){
                            hash_request(HASH_REQ_LAST, firmware_get_flip_base_addr(), dfu_header.len);
                        }
			else{
				goto err;
			}
                        while (status_reg.dma_done == false){
                                bool dma_error = status_reg.dma_fifo_err || status_reg.dma_dm_err || status_reg.dma_tr_err;
				if(dma_error == true){
					/* We had a DMA error ... Get out */
					goto err;
				}
			}
			uint8_t digest[SHA256_DIGEST_SIZE];
			if(hash_get_digest(digest, sizeof(digest), HASH_SHA256)){
				goto err;
			}
#if SMART_DEBUG
                        printf("hash done, the hash value is:\n");
			hexdump(digest, SHA256_DIGEST_SIZE);
#endif

	if(check_signature(&dfu_header, firmware_sig, digest, sizeof(digest)) != sectrue){
#if SMART_DEBUG
		printf("Firmware signature is NOK ...\n");
#endif
		goto err;
	}

#if SMART_DEBUG
		printf("Firmware signature is OK!\n");
#endif
            /* going to FLASHUPDATE state */
            set_task_state(DFUSMART_STATE_FLASHUPDATE);

            if (token_unmap()) {
#if SMART_DEBUG
                printf("Unable to map token!\n");
#endif
                goto err;
            }
            if (cryp_unmap()) {
#if SMART_DEBUG
                printf("Unable to map cryp!\n");
#endif
                goto err;
            }
            set_fw_header(&dfu_header, firmware_sig, digest);
            if (cryp_map()) {
#if SMART_DEBUG
                printf("Unable to map cryp!\n");
#endif
                goto err;
            }
            if (token_map()) {
#if SMART_DEBUG
                printf("Unable to map token!\n");
#endif
                goto err;
            }

            /* We consider that we can now reboot synchronously, as the upgrade is finished.
             * The device will boot in nominal mode on the new firmware */
            sys_reset();

            ipc_sync_cmd.magic = MAGIC_DFU_DWNLOAD_FINISHED;
            ipc_sync_cmd.state = SYNC_DONE;
            sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

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

                case MAGIC_DFU_GET_FW_VERSION:
                    {
                        if (is_valid_transition(get_task_state(), MAGIC_DFU_GET_FW_VERSION) != sectrue) {
                            goto bad_transition;
                        }
#if SMART_DEBUG
                        printf("PIN require current FW version\n");
#endif
                        if (token_unmap()) {
#if SMART_DEBUG
                            printf("Unable to map token!\n");
#endif
                            goto err;
                        }
                        uint32_t version = fw_get_current_version(FW_VERSION_FIELD_ALL);
#if SMART_DEBUG
                        printf("cur version: %x\n", version);
#endif
                        if (token_map()) {
#if SMART_DEBUG
                            printf("Unable to map token!\n");
#endif
                            goto err;
                        }
                        ipc_sync_cmd_data.magic = MAGIC_DFU_GET_FW_VERSION;
                        ipc_sync_cmd_data.state = SYNC_DONE;
                        ipc_sync_cmd_data.data_size = 1;
                        ipc_sync_cmd_data.data.u32[0] = version;

                        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);
                        break;
                    }
                /********* set user pin into smartcard *******/
                case MAGIC_SETTINGS_CMD:
                    {

                        if (is_valid_transition(get_task_state(), MAGIC_SETTINGS_CMD) != sectrue) {
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
#if SMART_DEBUG
                            printf("PIN require a Pet Pin update\n");
#endif

                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_PET_PIN };
                            if(dfu_token_unlock_ops_exec(dfu_get_token_channel(), ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0, NULL, 0)){
#if SMART_DEBUG
                                printf("Unable to change pet pin!!!\n");
#endif
                                continue;
                            }
#if SMART_DEBUG
                            printf("New pet pin registered\n");
#endif
                        } else if (   ipc_sync_cmd_data.data.req.sc_type == SC_USER_PIN
                                   && ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY) {
                            /* set the new pet pin. The CRYPTO_DFU_CMD must have been passed and the channel being unlocked */
#if SMART_DEBUG
                            printf("PIN require a User Pin update\n");
#endif

                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_USER_PIN };
                            if(dfu_token_unlock_ops_exec(dfu_get_token_channel(), ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0, NULL, 0)){
#if SMART_DEBUG
                                printf("Unable to change user pin!!!\n");
#endif
                                continue;
                            }
#if SMART_DEBUG
                            printf("New user pin registered\n");
#endif
                        } else if (   ipc_sync_cmd_data.data.req.sc_type == SC_PET_NAME
                                   && ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY) {
                            /* set the new pet pin. The CRYPTO_DFU_CMD must have been passed and the channel being unlocked */
#if SMART_DEBUG
                            printf("PIN require a Pet Name update\n");
#endif
                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_PET_NAME };
                            if(dfu_token_unlock_ops_exec(dfu_get_token_channel(), ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0, NULL, 0)){
#if SMART_DEBUG
                                printf("Unable to change pet name!!!\n");
#endif
                                continue;
                            }
#if SMART_DEBUG
                            printf("New pet name registered\n");
#endif
                        } else {
#if SMART_DEBUG
                            printf("Invalid PIN command bag : sc_type = %d, sc_req = %d!\n",
                                    ipc_sync_cmd_data.data.req.sc_type,
                                    ipc_sync_cmd_data.data.req.sc_req);
#endif
                        }
                        break;
                    }

                /********* lock the device (by rebooting) ***/
                case MAGIC_SETTINGS_LOCK:
                    {

                        if (is_valid_transition(get_task_state(), MAGIC_SETTINGS_LOCK) != sectrue) {
                            goto bad_transition;
                        }
                        sys_reset();
                        while (1);
                        break;
                    }




                    /********* defaulting to none    *************/
                default:
                    {
#if SMART_DEBUG
                        printf("unknown request !!!\n");
#endif
                        // FIXME: to be added: goto bad_transition;
                        // Although, there is still a HEADER_VALID IPC
                        // reception at DWNLOAD time that should be understood
                        // before...
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
