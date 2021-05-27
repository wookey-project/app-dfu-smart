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

#ifndef AUTOMATON_H_
#define AUTOMATON_H_

#include "libc/types.h"
#include "wookey_ipc.h"

typedef enum {
    DFUSMART_STATE_INIT = 0,
    DFUSMART_STATE_IDLE,
    DFUSMART_STATE_HEADER,
    DFUSMART_STATE_AUTH,
    DFUSMART_STATE_DWNLOAD,
    DFUSMART_STATE_CHECKSIG,
    DFUSMART_STATE_FLASHUPDATE,
    DFUSMART_STATE_ERROR
} t_dfusmart_state;

t_dfusmart_state get_task_state(void);

t_dfusmart_state get_next_state(t_dfusmart_state state, uint8_t magic);

void set_task_state(t_dfusmart_state state);

secbool is_valid_transition(t_dfusmart_state state, uint8_t magic);

#if SMART_DEBUG
const char *get_state_name(t_dfusmart_state state);
#endif

#endif/*!AUTOMATON_H_*/
