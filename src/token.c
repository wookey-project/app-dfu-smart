#include "main.h"
#include "token.h"
#include "wookey_ipc.h"

extern uint8_t id_pin; /* should be replaced by a getter */

token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 }, .pbkdf2_iterations = 0, .platform_salt_len = 0 };

token_channel *dfu_get_token_channel(void)
{
    return &curr_token_channel;
}

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
    } while (ret == SYS_E_BUSY);

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (   ipc_sync_cmd.magic == resp_magic
            && ipc_sync_cmd.state == SYNC_DONE) {
#if SMART_DEBUG
        printf("received pin from PIN\n");
#endif
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
#if SMART_DEBUG
        printf("received pet name from PIN: %s, size: %d\n",
                (char*)ipc_sync_cmd_data.data.u8,
                ipc_sync_cmd_data.data_size);
#endif
        if(*pet_name_len < ipc_sync_cmd_data.data_size){
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

/* [RB] NOTE: since sending APDUs during heavily loaded tasks scheduling is challenging, we have to deal with possible
 * smartcard secure channel loss ... In order to recover from such an issue, we try to renegotiate the secure channel
 * using saved keys. This is not satisfying from a security perspective: we want to forget/erase such keys asap. However,
 * from an end user perspective, providing the PINs each time a desynchronization is detected can be very painful.
 * One should notice that such a recovery system is specifically necessary during DFU since the USB task is on heavy duty
 * with keep alive requests from the host to answer with timing constraints ...
 */
int dfu_token_begin_decrypt_session_with_error(token_channel *channel, const unsigned char *header, uint32_t header_len, const databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num){
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
		ret = dfu_token_begin_decrypt_session(channel, header, header_len);
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
		if(token_secure_channel_init(channel, saved_decrypted_keybag[1].data, saved_decrypted_keybag[1].size, saved_decrypted_keybag[2].data, saved_decrypted_keybag[2].size, saved_decrypted_keybag[0].data, saved_decrypted_keybag[0].size, curve, &remaining_tries)){
			ret = -1;
			goto err;
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
            ret = -1;
            goto err;
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
    memcpy(ipc_sync_cmd.data.req.sc_petname, pet_name, pet_name_len);

#if SMART_DEBUG
    printf("requesting Pet name confirmation from PIN\n");
#endif
    do {
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);


#if SMART_DEBUG
    printf("waiting for acknowledge from PIN for Pet name...\n");
#endif
    /* receiving user acknowledge for pet name */
    size = sizeof(struct sync_command);
    id = id_pin;
    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

    if (ipc_sync_cmd.magic != MAGIC_CRYPTO_PIN_RESP ||
        ipc_sync_cmd.state != SYNC_ACKNOWLEDGE) {
        printf("[AUTH Token] Pen name has not been acknowledged by the user\n");
        goto err;
    }

#if SMART_DEBUG
    printf("[AUTH Token] Pen name acknowledge by the user\n");
#endif

    return 0;
err:
	return -1;
}

