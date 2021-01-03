#!/usr/bin/env sed

/^MEMORY$/ {
    n;
    n;
    s/^/  BKP_SRAM (r)       : ORIGIN = 0x40024000, LENGTH = 4*1023\n/;
    s/^/  \/* Backup SRAM, safe against RDP2->RDP1 downgrade *\/\n/;
    s/^/  NOUPGRADE_AUTH (r) : ORIGIN = 0x08100000, LENGTH = 4*1023\n/;
    s/^/  NOUPGRADE_DFU  (r) : ORIGIN = 0x08101000, LENGTH = 4*1023\n/;
    s/^/  NOUPGRADE_SIG  (r) : ORIGIN = 0x08102000, LENGTH = 4*1023\n/;
    s/^/  \/* keybag storage, not upgradable through DFU *\/\n/;
}

$s/^\}$/\
      \/* keybag storage sections *\/\n\
      .noupgrade_auth       :\n      {\n          _s_noupgrade_auth = .;      \n          *(.noupgrade.auth)            \n           _e_noupgrade_auth = .;      \n          . = ALIGN(4);\n      }>BKP_SRAM\n\
      .noupgrade_auth_flash :\n      {\n          _s_noupgrade_auth_flash = .;\n          KEEP(*(.noupgrade.auth.flash))\n           _e_noupgrade_auth_flash = .;\n          . = ALIGN(4);\n      }>NOUPGRADE_AUTH\n\
      .noupgrade_dfu        :\n      {\n          _s_noupgrade_dfu = .;       \n          *(.noupgrade.dfu)             \n           _e_noupgrade_dfu = .;       \n          . = ALIGN(4);\n      }>BKP_SRAM\n\
      .noupgrade_dfu_flash  :\n      {\n          _s_noupgrade_dfu_flash = .; \n          KEEP(*(.noupgrade.dfu.flash)) \n           _e_noupgrade_dfu_flash = .; \n          . = ALIGN(4);\n      }>NOUPGRADE_DFU\n\
      .noupgrade_sig        :\n      {\n          _s_noupgrade_sig = .;       \n          *(.noupgrade.sig)             \n           _e_noupgrade_sig = .;       \n          . = ALIGN(4);\n      }>BKP_SRAM AT>NOUPGRADE_SIG\n\
      .noupgrade_sig_flash  :\n      {\n          _s_noupgrade_sig_flash = .; \n          KEEP(*(.noupgrade.sig.flash)) \n           _e_noupgrade_sig_flash = .; \n      }>NOUPGRADE_SIG\n}/
