#ifndef TOKEN_H_
#define TOKEN_H_

#include "autoconf.h"
#include "api/syscall.h"
#include "api/print.h"
#include "api/types.h"
#include "libtoken_dfu.h"

token_channel *dfu_get_token_channel(void);

int dfu_token_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action);

int dfu_token_acknowledge_pin(token_ack_state ack, token_pin_types pin_type, token_pin_actions action, uint32_t remaining_tries);

int dfu_token_request_pet_name(char *pet_name, unsigned int *pet_name_len);

int dfu_token_begin_decrypt_session_with_error(token_channel *channel, const unsigned char *header, uint32_t header_len, const databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num);

int dfu_token_derive_key_with_error(token_channel *channel, unsigned char *derived_key, uint32_t derived_key_len, uint16_t num_chunk, const databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num);

int dfu_token_request_pet_name_confirmation(const char *pet_name, unsigned int pet_name_len);

#endif/*!TOKEN_H_*/
