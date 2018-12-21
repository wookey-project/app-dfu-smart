#include "automaton.h"
#include "main.h"
#include "api/print.h"

static volatile t_dfusmart_state task_state = DFUSMART_STATE_INIT;

#if SMART_DEBUG
static const char *state_tab[] = {
    "DFUSMART_STATE_INIT",
    "DFUSMART_STATE_IDLE",
    "DFUSMART_STATE_HEADER",
    "DFUSMART_STATE_AUTH",
    "DFUSMART_STATE_DWNLOAD",
    "DFUSMART_STATE_CHECKSIG",
    "DFUSMART_STATE_FLASHUPDATE",
    "DFUSMART_STATE_ERROR",
};

const char *get_state_name(t_dfusmart_state state)
{
    return state_tab[state];
}
#endif

typedef struct dfusmart_request_transition {
    uint8_t    request;
    uint8_t    target_state;
} dfusmart_request_transition_t;


static const struct {
    t_dfusmart_state               state;
    dfusmart_request_transition_t  req_trans[5];
} smart_automaton[] = {
    /* initialization phase. init specific IPC should be added here... no filter by now. */
    { DFUSMART_STATE_INIT,  {
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff}
                             }
    },
    /* setting Pin, passphrase, etc. is allowed only in IDLE phase. */
    { DFUSMART_STATE_IDLE,  {
                                 {MAGIC_SETTINGS_LOCK,DFUSMART_STATE_IDLE},
                                 {MAGIC_SETTINGS_CMD,DFUSMART_STATE_IDLE},
                                 {MAGIC_DFU_HEADER_SEND,DFUSMART_STATE_HEADER},
                                 {0xff,0xff},
                                 {0xff,0xff}
                             }
    },
    /* Get header phase, during which DFUUSB send the header to Smart */
    { DFUSMART_STATE_HEADER, {
                                 {MAGIC_DFU_HEADER_SEND,DFUSMART_STATE_HEADER},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff}
                             }
    },
    /* Auth phase, the header is authenticated by the smartcard (integrity) and the user (is it the firmware he's downloading right now ?) */
    { DFUSMART_STATE_AUTH,   {
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff}
                             }
    },
    /* Download phase, the firmware is downloaded, Smart manages the IV round */
    { DFUSMART_STATE_DWNLOAD, {
                                 {MAGIC_CRYPTO_INJECT_CMD,DFUSMART_STATE_DWNLOAD},
                                 {MAGIC_DFU_DWNLOAD_FINISHED,DFUSMART_STATE_CHECKSIG},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff}
                             }
    },
    /* End of download, Smart check the written firmware integrity with the smartcard */
    { DFUSMART_STATE_CHECKSIG, {
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff}
                             }
    },
    /* End of checksig, smart upate the flip/flop indicator to boot on the new firmware */
    { DFUSMART_STATE_FLASHUPDATE, {
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff}
                             }
    },
    /* Any error make smart going to this state. In production mode, this means rebooting the device */
    { DFUSMART_STATE_ERROR, {
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff},
                                 {0xff,0xff}
                             }
    },

};


t_dfusmart_state get_task_state(void)
{
    return task_state;
}

t_dfusmart_state get_next_state(t_dfusmart_state state, uint8_t magic)
{
    for (uint8_t i = 0; i < 5; ++i) {
        if (smart_automaton[state].req_trans[i].request == magic) {
            return (smart_automaton[state].req_trans[i].target_state);
        }
    }
    /* fallback, no corresponding request found for  this state */
    return 0xff;
}


void set_task_state(t_dfusmart_state state)
{
#if SMART_DEBUG
    printf("state: %s => %s\n", state_tab[task_state], state_tab[state]);
#endif
    task_state = state;
}

bool is_valid_transition(t_dfusmart_state state, uint8_t magic)
{
    /* FIXME: need automaton tab to be written */
    for (uint8_t i = 0; i < 5; ++i) {
        if (smart_automaton[state].req_trans[i].request == magic) {
            return true;
        }
    }
    return false;
}

