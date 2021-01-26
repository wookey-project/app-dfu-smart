#include "main.h"
#include "token.h"
#include "wookey_ipc.h"
#include "libc/sanhandlers.h"

extern uint8_t id_pin; /* should be replaced by a getter */

token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 }, .pbkdf2_iterations = 0, .platform_salt_len = 0 };

token_channel *dfu_get_token_channel(void)
{
    return &curr_token_channel;
}

/* [RB] NOTE: since sending APDUs during heavily loaded tasks scheduling is challenging, we have to deal with possible
 * smartcard secure channel loss ... In order to recover from such an issue, we try to renegotiate the secure channel
 * using saved keys. This is not satisfying from a security perspective: we want to forget/erase such keys asap. However,
 * from an end user perspective, providing the PINs each time a desynchronization is detected can be very painful.
 * One should notice that such a recovery system is specifically necessary during DFU since the USB task is on heavy duty
 * with keep alive requests from the host to answer with timing constraints ...
 */
#define MAX_PIN_SIZE	 	16
static uint8_t saved_pet_pin[MAX_PIN_SIZE] = { 0 };
static volatile unsigned int saved_pet_pin_len = 0;
static uint8_t saved_user_pin[MAX_PIN_SIZE] = { 0 };
static volatile unsigned int saved_user_pin_len = 0;
static volatile uint8_t saved_pin_action = 0;
#define MAX_PET_NAME_LEN  	32
static uint8_t saved_pet_name[MAX_PET_NAME_LEN] = { 0 };
static volatile unsigned int saved_pet_name_len = 0;

#define ATTR_UNUSED __attribute__((unused))

static int dfu_error_token_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action)
{
    if(action == TOKEN_PIN_AUTHENTICATE){
        if(pin_type == TOKEN_PET_PIN){
            if(*pin_len < saved_pet_pin_len){
                goto err;
            }
            else{
                memcpy(pin, saved_pet_pin, saved_pet_pin_len);
                *pin_len = saved_pet_pin_len;
            }
        }
        else if(pin_type == TOKEN_USER_PIN){
            if(*pin_len < saved_user_pin_len){
                goto err;
            }
            else{
                memcpy(pin, saved_user_pin, saved_user_pin_len);
                *pin_len = saved_user_pin_len;
            }
        }
        else{
            goto err;
        }
    }
    else{
        goto err;
    }

    return 0;

err:
    return -1;
}

static int dfu_error_token_acknowledge_pin(ATTR_UNUSED token_ack_state ack, ATTR_UNUSED token_pin_types pin_type, ATTR_UNUSED token_pin_actions action, ATTR_UNUSED uint32_t remaining_tries)
{
    return 0;
}

static int dfu_error_token_request_pet_name_confirmation(const char *pet_name, unsigned int pet_name_len)
{
    if(saved_pet_name_len != pet_name_len){
        goto err;
    }
    if(memcmp(&saved_pet_name, pet_name, pet_name_len) != 0){
        goto err;
    }
    return 0;

err:
    return -1;
}

/* Token error callbacks */
cb_token_callbacks dfu_error_token_callbacks = {
    .request_pin                   = dfu_error_token_request_pin,
    .acknowledge_pin               = dfu_error_token_acknowledge_pin,
    .request_pet_name              = NULL,
    .request_pet_name_confirmation = dfu_error_token_request_pet_name_confirmation
};
/* Register our calbacks */
ADD_GLOB_HANDLER(dfu_error_token_request_pin)
ADD_GLOB_HANDLER(dfu_error_token_acknowledge_pin)
ADD_GLOB_HANDLER(dfu_error_token_request_pet_name_confirmation)


/****************************************************************/
int dfu_token_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action)
{
    struct sync_command_data ipc_sync_cmd = { 0 };
    uint8_t ret;
    uint8_t id;
    logsize_t size = 0;
    uint32_t cmd_magic;
    uint32_t resp_magic;

    if(action == TOKEN_PIN_AUTHENTICATE){
#if SMART_DEBUG
        printf("Request PIN for authentication\n");
#endif
        ipc_sync_cmd.data.req.sc_req = SC_REQ_AUTHENTICATE;
    }
    else if (action == TOKEN_PIN_MODIFY){
#if SMART_DEBUG
        printf("Request PIN for modification\n");
#endif
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
#if SMART_DEBUG
        printf("Ask pet pin to PIN task\n");
#endif
        ipc_sync_cmd.data.req.sc_type = SC_PET_PIN;
    } else if (pin_type == TOKEN_USER_PIN){
#if SMART_DEBUG
	printf("Ask user pin to PIN task\n");
#endif
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
    } while (ret != SYS_E_DONE);

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if(ret != SYS_E_DONE){
        goto err;
    }
    if (   (ipc_sync_cmd.magic == resp_magic)
            && (ipc_sync_cmd.state == SYNC_DONE)) {
#if SMART_DEBUG
        printf("received pin from PIN\n");
#endif
        if((*pin_len) < ipc_sync_cmd.data_size){
              goto err;
        }
        memcpy(pin, (void*)&(ipc_sync_cmd.data.u8), ipc_sync_cmd.data_size);
        *pin_len = ipc_sync_cmd.data_size;
        /* Save our pin */
        if(action == TOKEN_PIN_AUTHENTICATE){
            if(*pin_len > MAX_PIN_SIZE){
                goto err;
            }
            if(pin_type == TOKEN_PET_PIN){
                memcpy(&saved_pet_pin, pin, *pin_len);
                saved_pet_pin_len = *pin_len;
            }
            else if(pin_type == TOKEN_USER_PIN){
                memcpy(&saved_user_pin, pin, *pin_len);
                saved_user_pin_len = *pin_len;
            }
            else{
                goto err;
            }
        }

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
#if SMART_DEBUG
        printf("acknowledge authentication PIN\n");
#endif
        /* int acknowledge of authentication, returning remaining tries */
        ipc_sync_cmd.data.u32[0] = remaining_tries;
        ipc_sync_cmd.data_size = 4;
    }
    else if (action == TOKEN_PIN_MODIFY){
#if SMART_DEBUG
        printf("acknowledge modification PIN\n");
#endif
    }
    else{
        goto err;
    }


    if ((pin_type == TOKEN_USER_PIN) || (pin_type == TOKEN_PET_PIN)) {
       ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
    } else {
        goto err;
    }
    if(ack == TOKEN_ACK_VALID){
    	ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;
    } else{
    	ipc_sync_cmd.state = SYNC_FAILURE;
    }
    ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
#if SMART_DEBUG
        printf("unable to acknowledge!\n");
#endif
        goto err;
    }

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
    } while (ret != SYS_E_DONE);

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
    if(ret != SYS_E_DONE){
        goto err;
    }
    if (   (ipc_sync_cmd_data.magic == resp_magic)
            && (ipc_sync_cmd_data.state == SYNC_DONE)) {
#if SMART_DEBUG
        printf("received pet name from PIN: %s, size: %d\n",
                (char*)ipc_sync_cmd_data.data.u8,
                ipc_sync_cmd_data.data_size);
#endif
        if((*pet_name_len) < ipc_sync_cmd_data.data_size){
#if SMART_DEBUG
              printf("pet name len (%d) too long !\n", ipc_sync_cmd_data.data_size);
#endif
              goto err;
        }
        memcpy(pet_name, (void*)&(ipc_sync_cmd_data.data.u8), ipc_sync_cmd_data.data_size);
        *pet_name_len = ipc_sync_cmd_data.data_size;
        return 0;
    }

err:
    return -1;
}


extern int wrap_dfu_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, unsigned char *decrypted_sig_pub_key_data, unsigned int *decrypted_sig_pub_key_data_len, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num);

/* [RB] NOTE: since sending APDUs during heavily loaded tasks scheduling is challenging, we have to deal with possible
 * smartcard secure channel loss ... In order to recover from such an issue, we try to renegotiate the secure channel
 * using saved keys. This is not satisfying from a security perspective: we want to forget/erase such keys asap. However,
 * from an end user perspective, providing the PINs each time a desynchronization is detected can be very painful.
 * One should notice that such a recovery system is specifically necessary during DFU since the USB task is on heavy duty
 * with keep alive requests from the host to answer with timing constraints ...
 */
#define MAX_HEADER_SIZE		1024
static unsigned char saved_header[MAX_HEADER_SIZE] = { 0 };
static volatile uint32_t saved_header_len = 0;

int dfu_token_begin_decrypt_session_with_error(token_channel *channel, const unsigned char *header, uint32_t header_len, const databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num){
        unsigned int num_tries;
        int ret = 0;
        num_tries = 0;
	unsigned int remaining_tries = 0;
        ec_curve_type curve;

	/* Sanity check */
        if(header == NULL){
                printf("Header NULL\n");
		ret = -1;
		goto err;
        }
	if(saved_decrypted_keybag_num < 3){
                printf("not enough decrypted keybag %d\n", saved_decrypted_keybag_num);
		ret = -1;
		goto err;
	}
	if((channel == NULL) || (channel->curve == UNKNOWN_CURVE)){
                printf("invalid channel or curve %x\n", channel);
		ret = -1;
		goto err;
	}
	curve = channel->curve;
    while(1){
        ret = dfu_token_begin_decrypt_session(channel, header, header_len);
        num_tries++;
        if(!ret){
            if(header_len > sizeof(saved_header)){
                ret = -1;
                goto err;
            }
            saved_header_len = header_len;
            memcpy(saved_header, header, header_len);
            return 0;
        }
        if(ret == -2){
            /* We cannot start our session because of a malformed/bad header from the token point of view ... */
            printf("bad token header\n");
            ret = -2;
            goto err;
        }
        if(ret && (num_tries >= channel->error_recovery_max_send_retries)){
            ret = -1;
            goto err;
        }
        /* We try to renegotiate a secure channel */
        token_zeroize_secure_channel(channel);
        if(token_secure_channel_init(channel, saved_decrypted_keybag[1].data, saved_decrypted_keybag[1].size, saved_decrypted_keybag[2].data, saved_decrypted_keybag[2].size, saved_decrypted_keybag[0].data, saved_decrypted_keybag[0].size, curve, &remaining_tries)){
            printf("unable to initialize secure channel\n");
            /* Last chance, reinitialize entirely communication with the token */
            extern unsigned char decrypted_sig_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
            extern unsigned int decrypted_sig_pub_key_data_len;
            if(wrap_dfu_token_exchanges(channel, &dfu_error_token_callbacks, decrypted_sig_pub_key_data, &decrypted_sig_pub_key_data_len, NULL, 0))
            {
                ret = -1;
                goto err;
            }
        }
    }

err:
    return ret;
}


int dfu_token_derive_key_with_error(token_channel *channel, unsigned char *derived_key, uint32_t derived_key_len, uint16_t num_chunk, const databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num)
{
    unsigned int num_tries;
    int ret = 0;
    num_tries = 0;
    unsigned int remaining_tries = 0;
    ec_curve_type curve;

    /* Sanity check */
    if(saved_decrypted_keybag_num < 3){
        ret = -1;
        goto err;
    }
    if((channel == NULL) || (channel->curve == UNKNOWN_CURVE)){
        ret = -1;
        goto err;
    }
    curve = channel->curve;
    while(1){
        ret = dfu_token_derive_key(channel, derived_key, derived_key_len, num_chunk);
        num_tries++;
        if(!ret){
            return 0;
        }
        if(ret && (num_tries >= channel->error_recovery_max_send_retries)){
            ret = -1;
            goto err;
        }
        /* We try to renegotiate a secure channel */
        token_zeroize_secure_channel(channel);
        if(token_secure_channel_init(channel, saved_decrypted_keybag[1].data, saved_decrypted_keybag[1].size, saved_decrypted_keybag[2].data, saved_decrypted_keybag[2].size, saved_decrypted_keybag[0].data, saved_decrypted_keybag[0].size, curve, &remaining_tries))
        {
            printf("unable to initialize secure channel\n");
            /* Last chance, reinitialize entirely communication with the token */
            extern unsigned char decrypted_sig_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
            extern unsigned int decrypted_sig_pub_key_data_len;
            if(wrap_dfu_token_exchanges(channel, &dfu_error_token_callbacks, decrypted_sig_pub_key_data, &decrypted_sig_pub_key_data_len, NULL, 0))
            {
                ret = -1;
                goto err;
            }
            /* Open our decryption session again */
            if(dfu_token_begin_decrypt_session_with_error(channel, saved_header, saved_header_len, saved_decrypted_keybag, saved_decrypted_keybag_num)){
                ret = -1;
                goto err;
            }
        }
    }

err:
    return ret;
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
    if(pet_name_len > sizeof(ipc_sync_cmd.data.req.sc_petname)){
        printf("pet name length %d too long!\n", pet_name_len);
        goto err;
    }
    memcpy(ipc_sync_cmd.data.req.sc_petname, pet_name, pet_name_len);

#if SMART_DEBUG
    printf("requesting Pet name confirmation from PIN\n");
#endif
    do {
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);


#if SMART_DEBUG
    printf("waiting for acknowledge from PIN for Pet name...\n");
#endif
    /* receiving user acknowledge for pet name */
    size = sizeof(struct sync_command);
    id = id_pin;
    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if(ret != SYS_E_DONE){
        goto err;
    }

    if ((ipc_sync_cmd.magic != MAGIC_CRYPTO_PIN_RESP) ||
        (ipc_sync_cmd.state != SYNC_ACKNOWLEDGE)) {
#if SMART_DEBUG
        printf("[AUTH Token] Pen name has not been acknowledged by the user\n");
#endif
        goto err;
    }

#if SMART_DEBUG
    printf("[AUTH Token] Pen name acknowledge by the user\n");
#endif
    if(pet_name_len > sizeof(saved_pet_name)){
        goto err;
    }
    else{
        saved_pet_name_len = pet_name_len;
        memcpy(&saved_pet_name, pet_name, pet_name_len);
    }

    return 0;
err:
	return -1;
}

