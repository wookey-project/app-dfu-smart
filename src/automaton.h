#ifndef AUTOMATON_H_
#define AUTOMATON_H_

#include "api/types.h"
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
