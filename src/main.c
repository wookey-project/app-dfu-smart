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

/* Crypto helpers for DFU */
#include "dfu_header.h"

#define SMART_DEBUG 1

token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 }, .pbkdf2_iterations = 0, .platform_salt_len = 0 };
uint8_t id_pin = 0;

int dfu_token_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action)
{
    struct sync_command_data ipc_sync_cmd = { 0 };
    uint8_t ret;
    uint8_t id;
    logsize_t size = 0;
    uint32_t cmd_magic;
    uint32_t resp_magic;

    if(action == TOKEN_PIN_AUTHENTICATE){
        printf("Request PIN for authentication\n");
        ipc_sync_cmd.data.req.sc_req = SC_REQ_AUTHENTICATE;
    }
    else if (action == TOKEN_PIN_MODIFY){
        printf("Request PIN for modification\n");
        ipc_sync_cmd.data.req.sc_req = SC_REQ_MODIFY;
    }
    else{
        goto err;
    }

    /*********************************************
     * Request PIN to pin task
     *********************************************/
    cmd_magic = MAGIC_CRYPTO_PIN_CMD;
    resp_magic = MAGIC_CRYPTO_PIN_RESP;

    if(pin_type == TOKEN_PET_PIN){
        printf("Ask pet pin to PIN task\n");
        ipc_sync_cmd.data.req.sc_type = SC_PET_PIN;
    } else if (pin_type == TOKEN_USER_PIN){
	printf("Ask user pin to PIN task\n");
        ipc_sync_cmd.data.req.sc_type = SC_USER_PIN;
    }
    else{
	printf("Error: asking for unknown type pin ...\n");
	goto err;
    }
    ipc_sync_cmd.magic = cmd_magic;
    ipc_sync_cmd.state = SYNC_ASK_FOR_DATA;

    do {
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (   ipc_sync_cmd.magic == resp_magic
            && ipc_sync_cmd.state == SYNC_DONE) {
        printf("received pin from PIN\n");
        if(*pin_len < ipc_sync_cmd.data_size){
              goto err;
        }
        memcpy(pin, (void*)&(ipc_sync_cmd.data.u8), ipc_sync_cmd.data_size);
        *pin_len = ipc_sync_cmd.data_size;
        return 0;
    }

err:
    return -1;
}

int dfu_token_acknowledge_pin(token_ack_state ack, token_pin_types pin_type, token_pin_actions action, uint32_t remaining_tries)
{
    struct sync_command_data   ipc_sync_cmd = { 0 };
    uint8_t ret;

    if(action == TOKEN_PIN_AUTHENTICATE){
        printf("acknowledge authentication PIN\n");
        /* int acknowledge of authentication, returning remaining tries */
        ipc_sync_cmd.data.u32[0] = remaining_tries;
        ipc_sync_cmd.data_size = 4;
    }
    else if (action == TOKEN_PIN_MODIFY){
        printf("acknowledge modification PIN\n");
    }
    else{
        goto err;
    }


    if (pin_type == TOKEN_USER_PIN || pin_type == TOKEN_PET_PIN) {
       ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
    } else {
        goto err;
    }
    if(ack == TOKEN_ACK_VALID){
    	ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;
    } else{
    	ipc_sync_cmd.state = SYNC_FAILURE;
    }
    //do {
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
        if (ret != SYS_E_DONE) {
            printf("unable to acknowledge!\n");
            while (1);
        }
    //} while (ret == SYS_E_BUSY);

    /* an invalid pin is considered as an error, we stop here, returning an error. */
    if (ack != TOKEN_ACK_VALID) {
        goto err;
    }
	return 0;
err:
	return -1;
}

int dfu_token_request_pet_name(char *pet_name, unsigned int *pet_name_len)
{
    struct sync_command_data ipc_sync_cmd_data = { 0 };
    uint8_t ret;
    uint8_t id;
    logsize_t size = 0;
    uint32_t cmd_magic;
    uint32_t resp_magic;

    /*********************************************
     * Request PET name to pin task
     *********************************************/
    cmd_magic = MAGIC_CRYPTO_PIN_CMD;
    resp_magic = MAGIC_CRYPTO_PIN_RESP;

    ipc_sync_cmd_data.magic = cmd_magic;
    ipc_sync_cmd_data.state = SYNC_ASK_FOR_DATA;
    // TODO: set data_size please
    ipc_sync_cmd_data.data.req.sc_type = SC_PET_NAME;
    ipc_sync_cmd_data.data.req.sc_req = SC_REQ_MODIFY;

    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);
    } while (ret == SYS_E_BUSY);

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
    if (   ipc_sync_cmd_data.magic == resp_magic
            && ipc_sync_cmd_data.state == SYNC_DONE) {
        printf("received pet name from PIN: %s, size: %d\n",
                (char*)ipc_sync_cmd_data.data.u8,
                ipc_sync_cmd_data.data_size);
        if(*pet_name_len < ipc_sync_cmd_data.data_size){
              printf("pet name len (%d) too long !\n", ipc_sync_cmd_data.data_size);
              goto err;
        }
        memcpy(pet_name, (void*)&(ipc_sync_cmd_data.data.u8), ipc_sync_cmd_data.data_size);
        *pet_name_len = ipc_sync_cmd_data.data_size;
        return 0;
    }

err:
    return -1;
}



int dfu_token_request_pet_name_confirmation(const char *pet_name, unsigned int pet_name_len)
{
    /************* Send pet name to pin */
    struct sync_command_data ipc_sync_cmd = { 0 };
    logsize_t size = 0;
    uint8_t id = 0;
    uint8_t ret;

    ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_CMD;
    ipc_sync_cmd.state = SYNC_WAIT;
    ipc_sync_cmd.data.req.sc_type = SC_PET_NAME;
    ipc_sync_cmd.data.req.sc_req = SC_REQ_AUTHENTICATE;

    // FIXME: string length check to add
    memcpy(ipc_sync_cmd.data.req.sc_petname, pet_name, pet_name_len);

    printf("requesting Pet name confirmation from PIN\n");
    do {
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);


    printf("waiting for acknowledge from PIN for Pet name...\n");
    /* receiving user acknowledge for pet name */
    size = sizeof(struct sync_command);
    id = id_pin;
    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

    if (ipc_sync_cmd.magic != MAGIC_CRYPTO_PIN_RESP ||
        ipc_sync_cmd.state != SYNC_ACKNOWLEDGE) {
        printf("[AUTH Token] Pen name has not been acknowledged by the user\n");
        goto err;
    }

    printf("[AUTH Token] Pen name acknowledge by the user\n");

    return 0;
err:
	return -1;
}

void smartcard_removal_action(void){
    /* Check if smartcard has been removed, and reboot if yes */
    if((curr_token_channel.card.type != SMARTCARD_UNKNOWN) && !SC_is_smartcard_inserted(&(curr_token_channel.card))){
        SC_smartcard_lost(&(curr_token_channel.card));
        sys_reset();
    }	
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


#if CONFIG_WOOKEY
    /* toggle led ON */
    sys_cfg(CFG_GPIO_SET, (uint8_t)((('C' - 'A') << 4) + 5), 1);
#endif

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
 
    /*********************************************
     * Wait for crypto to ask for key injection
     *********************************************/

    /* First, wait for pin to finish its init phase */
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

    /* Register smartcard removal handler */
    curr_token_channel.card.type = SMARTCARD_CONTACT;
    SC_register_user_handler_action(&(curr_token_channel.card), smartcard_removal_action);
    curr_token_channel.card.type = SMARTCARD_UNKNOWN;
    
    /* Token callbacks */
    cb_token_callbacks dfu_token_callbacks = {
        .request_pin                   = dfu_token_request_pin,
        .acknowledge_pin               = dfu_token_acknowledge_pin,
        .request_pet_name              = dfu_token_request_pet_name,
        .request_pet_name_confirmation = dfu_token_request_pet_name_confirmation
    };
    /* this call generates authentication request to PIN */
    /* NB: we get back our decrypted signature public key here */
    unsigned char decrypted_sig_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
    unsigned int decrypted_sig_pub_key_data_len = sizeof(decrypted_sig_pub_key_data);
    if(!tokenret && dfu_token_exchanges(&curr_token_channel, &dfu_token_callbacks, decrypted_sig_pub_key_data, &decrypted_sig_pub_key_data_len))
    {
        goto err;
    }
#ifdef SMART_DEBUG
    printf("Decrypted signature public key (size %d):\n", decrypted_sig_pub_key_data_len);
    hexdump(decrypted_sig_pub_key_data, decrypted_sig_pub_key_data_len);
#endif

    /* Now that we have received our assets, we can lock the token.
     * We maintain the secure channel opened for a while, we only lock the
     * user PIN for now.
     */
    if(token_user_pin_lock(&curr_token_channel)){ 
        goto err;
    }

    printf("cryptography and smartcard initialization done!\n");

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
                        // A DFU header has been received: get it and parse it
#ifdef SMART_DEBUG
                        printf("We have a DFU header IPC, start receiveing\n");
#endif
                        uint32_t tmp_buff_offset = 0;
                        while(ipc_sync_cmd_data.data_size != 0){
                            if((id != id_crypto) || (ipc_sync_cmd_data.magic != MAGIC_DFU_HEADER_SEND)){
#ifdef SMART_DEBUG
                                printf("Error during DFU header receive ...\n");
                                goto err;
#endif
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

                        if(dfu_parse_header(tmp_buff, sizeof(tmp_buff), &dfu_header, sig, sizeof(sig))){
#ifdef SMART_DEBUG
                            printf("Error: bad header received from USB through crypto!\n");
#endif
                            ipc_sync_cmd.magic = MAGIC_DFU_HEADER_INVALID;
                            ipc_sync_cmd.state = SYNC_DONE;
                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

                            continue;

                        }
#ifdef SMART_DEBUG
                        dfu_print_header(&dfu_header);
#endif
#if 0 /* FIXME: not operational yet !!!*/
                        /* now let's ask the user for validation */
                        ipc_sync_cmd_data.magic = MAGIC_DFU_HEADER_SEND;
                        ipc_sync_cmd_data.state = SYNC_DONE;
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
#endif


                        /* PIN said it is okay, continuing */

                        memset((void*)&ipc_sync_cmd_data, 0, sizeof(struct sync_command_data));
                        ipc_sync_cmd_data.magic = MAGIC_DFU_HEADER_VALID;
                        ipc_sync_cmd_data.state = SYNC_DONE;
                        ipc_sync_cmd_data.data.u16[0] = sizeof(dfu_header) + dfu_header.siglen;
                        ipc_sync_cmd_data.data_size = 1;
                        sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

//                        dfu_token_begin_decrypt_session(&curr_token_channel, tmp_buf, sizeof(dfu_header));
                        break;
                    }


                /********* Key injection request *************/
                case MAGIC_CRYPTO_INJECT_CMD:
                    {
                        // A DFU chunk has been received. chunk id is passed
                        // in the received IPC

                        ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_RESP;
                        ipc_sync_cmd.state = SYNC_DONE;

                        sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
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
                            if(dfu_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0)){
                                printf("Unable to change pet pin!!!\n");
                                continue;
                            }
                            printf("New pet pin registered\n");
                        } else if (   ipc_sync_cmd_data.data.req.sc_type == SC_USER_PIN
                                   && ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY) {
                            /* set the new pet pin. The CRYPTO_DFU_CMD must have been passed and the channel being unlocked */
                            printf("PIN require a User Pin update\n");

                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_USER_PIN };
                            if(dfu_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0)){
                                printf("Unable to change user pin!!!\n");
                                continue;
                            }
                            printf("New user pin registered\n");
                        } else if (   ipc_sync_cmd_data.data.req.sc_type == SC_PET_NAME
                                   && ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY) {
                            /* set the new pet pin. The CRYPTO_DFU_CMD must have been passed and the channel being unlocked */
                            printf("PIN require a Pet Name update\n");
                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_PET_NAME };
                            if(dfu_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &dfu_token_callbacks, 0, 0)){
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
                        sys_reset();
                        while (1);
                        break;
                    }




                    /********* defaulting to none    *************/
                default:
                    {
                        break;
                    }
            }

        }

        // nothing ? just wait for next event
        sys_yield();
    }

    return 0;
err:
    printf("Oops\n");
    while (1) {
        sys_reset();
    }
    return 0;
}
