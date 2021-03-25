/*
 *
 * Copyright 2019 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef TOKEN_H_
#define TOKEN_H_

#include "autoconf.h"
#include "libc/syscall.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/types.h"
#include "libtoken_dfu.h"

token_channel *dfu_get_token_channel(void);

int dfu_token_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action);

int dfu_token_acknowledge_pin(token_ack_state ack, token_pin_types pin_type, token_pin_actions action, uint32_t remaining_tries);

int dfu_token_request_pet_name(char *pet_name, unsigned int *pet_name_len);

int dfu_token_begin_decrypt_session_with_error(token_channel *channel, const unsigned char *header, uint32_t header_len, const databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num);

int dfu_token_derive_key_with_error(token_channel *channel, unsigned char *derived_key, uint32_t derived_key_len, uint16_t num_chunk, const databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num);

int dfu_token_request_pet_name_confirmation(const char *pet_name, unsigned int pet_name_len);

#endif/*!TOKEN_H_*/
