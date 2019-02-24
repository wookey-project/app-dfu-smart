APP_NAME ?= dfusmart
DIR_NAME = dfusmart

PROJ_FILES = ../../
BIN_NAME = $(APP_NAME).bin
HEX_NAME = $(APP_NAME).hex
ELF_NAME = $(APP_NAME).elf

######### Metadata ##########
ifeq ($(APP_NAME),dfusmart)
    IMAGE_TYPE = IMAGE_TYPE0
else
    IMAGE_TYPE = IMAGE_TYPE1
endif

VERSION = 1
#############################

-include $(PROJ_FILES)/Makefile.conf
-include $(PROJ_FILES)/Makefile.gen

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/apps/$(DIR_NAME)

CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -Isrc/ -Iinc/
CFLAGS += $(APPS_CFLAGS)
CFLAGS += -I$(PROJ_FILES)/externals/libecc/src
CFLAGS += $(EXTERNAL_CFLAGS) -Os
CFLAGS += -Wl,-Map=$(APP_BUILD_DIR)/$(APP_NAME).map

LDFLAGS += -fno-builtin -nostdlib -nostartfiles $(AFLAGS_GCC) -Wl,-Map=$(APP_BUILD_DIR)/$(APP_NAME).map
#LDFLAGS += $(AFLAGS) -fno-builtin -nostdlib -nostartfiles -Wl,-Map=$(APP_BUILD_DIR)/$(APP_NAME).map

EXTRA_LDFLAGS ?= -Tdfusmart.fw1.ld
LDFLAGS += $(EXTRA_LDFLAGS) -L$(APP_BUILD_DIR) -fno-builtin -nostdlib --enable-objc-gc -Wl,--gc-sections
LD_LIBS += -ltoken -lsmartcard -liso7816 -ldrviso7816 -lcryp -lusart -laes -lhmac -lstd -lsign -lfirmware -lhash -lflash -L$(APP_BUILD_DIR)


BUILD_DIR ?= $(PROJ_FILE)build

CSRC_DIR = src
SRC = $(wildcard $(CSRC_DIR)/*.c)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(OBJ:.o=.d)

OUT_DIRS = $(dir $(OBJ))

LDSCRIPT_NAME = $(APP_BUILD_DIR)/$(APP_NAME).ld

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(OBJ) $(DEP) $(LDSCRIPT_NAME)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

show:
	@echo $(LIB_CFLAGS)

#############################################################
# build targets (driver, core, SoC, Board... and local)

all: $(APP_BUILD_DIR) alldeps app

############################################################
# eplicit dependency on the application libs and drivers
# compiling the application requires the compilation of its
# dependencies
#
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
             $(BUILD_DIR)/drivers/libiso7816/libiso7816.a \
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

app: $(APP_BUILD_DIR)/$(ELF_NAME) $(APP_BUILD_DIR)/$(HEX_NAME)

$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

# ELF
$(APP_BUILD_DIR)/$(ELF_NAME): $(OBJ)
	$(call if_changed,link_o_target)

# HEX
$(APP_BUILD_DIR)/$(HEX_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_ihex)

# BIN
$(APP_BUILD_DIR)/$(BIN_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_bin)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)
