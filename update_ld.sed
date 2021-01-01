#!/usr/bin/env sed

/^MEMORY$/ {
    n;
    n;
    s/^/  NOUPGRADE_AUTH (r) : ORIGIN = 0x08100000, LENGTH = 4*1024\n/;
    s/^/  NOUPGRADE_DFU  (r) : ORIGIN = 0x08101000, LENGTH = 4*1024\n/;
    s/^/  NOUPGRADE_SIG  (r) : ORIGIN = 0x08102000, LENGTH = 4*1024\n/;
    s/^/  \/* keybag storage, not upgradable through DFU *\/\n/;
}

$s/\}/    .noupgrade_auth :\n    {\n        _s_noupgrade_auth = .;\n        *(.noupgrade.auth)\n         _e_noupgrade_auth = .;\n        . = ALIGN(4);\n    }>NOUPGRADE_AUTH\n\
    .noupgrade_dfu :\n    {\n        _s_noupgrade_dfu = .;\n        *(.noupgrade.dfu)\n         _e_noupgrade_dfu = .;\n        . = ALIGN(4);\n    }>NOUPGRADE_DFU\n\
    .noupgrade_sig :\n    {\n        _s_noupgrade_sig = .;\n        *(.noupgrade.sig)\n         _e_noupgrade_sig = .;\n    }>NOUPGRADE_SIG\n}/
