###################################################################
# About the application name and path
###################################################################

# Application name, can be suffixed by the SDK
APP_NAME ?= dfusmart
APP_LDSCRIPT = $(patsubst -T%.ld,%.ld,$(filter -T%.ld, $(EXTRA_LDFLAGS)))
# application build directory name
DIR_NAME = dfusmart

# project root directory, relative to app dir
PROJ_FILES = ../../

# binary, hex and elf file names
BIN_NAME = $(APP_NAME).bin
HEX_NAME = $(APP_NAME).hex
ELF_NAME = $(APP_NAME).elf

# SDK helper Makefiles inclusion
-include $(PROJ_FILES)/m_config.mk
-include $(PROJ_FILES)/m_generic.mk

# application build directory, relative to the SDK BUILD_DIR environment
# variable.
APP_BUILD_DIR = $(BUILD_DIR)/apps/$(DIR_NAME)

###################################################################
# About the compilation flags
###################################################################

CFLAGS := $(APPS_CFLAGS)
# here we need libecc headers
CFLAGS += -I$(PROJ_FILES)/externals/libecc/src $(EXTERNAL_CFLAGS)

###################################################################
# About the link step
###################################################################

# linker options to add the layout file
LDFLAGS += $(EXTRA_LDFLAGS) -L$(APP_BUILD_DIR)

# project's library you whish to use...
LD_LIBS += -ltoken -lsmartcard -liso7816 -ldrviso7816 -lcryp -lusart -laes -lhmac -lstd -lsign -lfirmware -lhash -lflash -Wl,--no-whole-archive

###################################################################
# okay let's list our source files and generated files now
###################################################################

CSRC_DIR = src
SRC = $(wildcard $(CSRC_DIR)/*.c)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(OBJ:.o=.d)

# the output directories, that will be deleted by the distclean target
OUT_DIRS = $(dir $(OBJ))

# the ldcript file generated by the SDK
LDSCRIPT_NAME = $(APP_BUILD_DIR)/$(APP_NAME).ld

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(OBJ) $(DEP) $(LDSCRIPT_NAME)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

############################################################
# explicit dependency on the application libs and drivers
# compiling the application requires the compilation of its
# dependencies
############################################################

## library dependencies
LIBDEP := $(BUILD_DIR)/libs/libsmartcard/libsmartcard.a \
	      $(BUILD_DIR)/libs/libiso7816/libiso7816.a \
		  $(BUILD_DIR)/libs/libaes/libaes.a \
		  $(BUILD_DIR)/libs/libhmac/libhmac.a \
		  $(BUILD_DIR)/libs/libstd/libstd.a \
		  $(BUILD_DIR)/libs/token/libtoken.a \
		  $(BUILD_DIR)/libs/libfirmware/libfirmware.a


libdep: $(LIBDEP)

$(LIBDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)libs/$(patsubst lib%.a,%,$(notdir $@))


# drivers dependencies
SOCDRVDEP := $(BUILD_DIR)/drivers/libcryp/libcryp.a \
             $(BUILD_DIR)/drivers/libdrviso7816/libdrviso7816.a \
             $(BUILD_DIR)/drivers/libusart/libusart.a \
             $(BUILD_DIR)/drivers/libhash/libhash.a \
             $(BUILD_DIR)/drivers/libflash/libflash.a


socdrvdep: $(SOCDRVDEP)

$(SOCDRVDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)drivers/socs/$(SOC)/$(patsubst lib%.a,%,$(notdir $@))

# board drivers dependencies
BRDDRVDEP    :=

brddrvdep: $(BRDDRVDEP)

$(BRDDRVDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)drivers/boards/$(BOARD)/$(patsubst lib%.a,%,$(notdir $@))

# external dependencies
EXTDEP    := $(BUILD_DIR)/libs/libsign/libsign.a

extdep: $(EXTDEP)

$(EXTDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)externals


alldeps: libdep socdrvdep brddrvdep extdep

##########################################################
# generic targets of all applications makefiles
##########################################################

show:
	@echo
	@echo "\t\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\t\tSRC\t=> " $(SRC)
	@echo "\t\tOBJ\t=> " $(OBJ)
	@echo "\t\tDEP\t=> " $(DEP)
	@echo
	@echo "\t\tCFG\t=> " $(CFLAGS)

all: $(APP_BUILD_DIR) alldeps app

# DFUsmart is an app using a dedicated section, named
# 'NOUPDATE'. This section hold the encrypted keybag.
# Although, this section is not mapped by the task itself, but by the
# bootloader, which is responsible for copying the encrypted keybag
# from the NOUPDATE section to the SecureRAM.
# Smart access the keybag in the secureRAM directly.
# The goal, here, is to allow firmware upgrade without requiring the
# private AUTH key knowledge. Only the SIG key is required to build
# a fully functional firmware. To do this, the generated firmware image
# must be truncated of the NOUPGRADE secion, which should never be updated
#
# Here, we add NOUPGRADE memory layout and .noupgrade section to the
# generic app ldscripts before compiling and linking
#
update_ld:
	sed '/^$$/d' -i $(APP_BUILD_DIR)/$(APP_LDSCRIPT)
	sed -f update_ld.sed -i $(APP_BUILD_DIR)/$(APP_LDSCRIPT)

app: update_ld $(APP_BUILD_DIR)/$(ELF_NAME) $(APP_BUILD_DIR)/$(HEX_NAME)

$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

CROSS_OBJCOPY_ARGS="--keep-section=.noupgrade_dfu"
# ELF
$(APP_BUILD_DIR)/$(ELF_NAME): $(OBJ)
	$(call if_changed,link_o_target)
	$(OBJCOPY) $(APP_BUILD_DIR)/$(ELF_NAME) $(APP_BUILD_DIR)/$(ELF_NAME)

# HEX
$(APP_BUILD_DIR)/$(HEX_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_ihex)

# BIN
$(APP_BUILD_DIR)/$(BIN_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_bin)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)
