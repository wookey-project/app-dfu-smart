#ifndef MAIN_H_
# define MAIN_H_

typedef enum {
    DFUSMART_STATE_INIT = 1,
    DFUSMART_STATE_IDLE,
    DFUSMART_STATE_HEADER,
    DFUSMART_STATE_AUTH,
    DFUSMART_STATE_DWNLOAD,
    DFUSMART_STATE_CHECKSIG,
    DFUSMART_STATE_FLASHUPDATE,
    DFUSMART_STATE_ERROR
} t_dfusmart_state;

t_dfusmart_state
get_task_state(void);

void
set_task_state(t_dfusmart_state state);

#endif/*!MAIN_H_*/
