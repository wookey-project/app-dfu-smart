#!/usr/bin/env sed

/^MEMORY$/ {
    n;
    n;
    s/^/  BKP_SRAM (r)       : ORIGIN = 0x40024000, LENGTH = 1024\n/;
    s/^/  \/* Backup SRAM, safe against RDP2->RDP1 downgrade *\/\n/;
    s/^/  NOUPGRADE_AUTH (r) : ORIGIN = 0x08100000, LENGTH = 1024\n/;
    s/^/  NOUPGRADE_DFU  (r) : ORIGIN = 0x08100400, LENGTH = 1024\n/;
    s/^/  NOUPGRADE_SIG  (r) : ORIGIN = 0x08100800, LENGTH = 1024\n/;
    s/^/  \/* keybag storage, not upgradable through DFU *\/\n/;
}


$s/^\}$/\
  OVERLAY ORIGIN(BKP_SRAM) : NOCROSSREFS AT (ORIGIN(NOUPGRADE_DFU))\
  {\
      .noupgrade_dfu_bkup { *(.noupgrade.dfu) }\
      .noupgrade_auth_bkup { *(.noupgrade.auth) }\
      .noupgrade_sig_bkup { *(.noupgrade.sig) }\
  }\n}/
