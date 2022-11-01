ifeq ($(CC),cc)
CC=$(lastword $(subst /, ,$(shell readlink -f `which cc`)))
endif

ifeq ($(findstring gcc,$(CC)),gcc)
CFLAGS  += -Wno-stringop-truncation
LDFLAGS += -s
else
CFLAGS += -fno-temp-file
endif

PLATFORM ?= $(firstword $(subst -, ,$(CC)))
HOST ?= $(word 2, $(subst -, ,$(CC)))

SRC 		= .
BIN			= bin/climdnssd-$(HOST)-$(PLATFORM)
LIB			= lib/$(HOST)/$(PLATFORM)/libmdnssd.a
BUILDDIR	= bin/$(HOST)/$(PLATFORM)

CFLAGS  += -Wall -fPIC -ggdb -O2 $(DEFINES) -fdata-sections -ffunction-sections 

vpath %.c $(SRC)

INCLUDE = -I$(SRC) 

SOURCES =  mdnssd.c
	
OBJECTS = $(SOURCES:%.c=$(BUILDDIR)/%.o) 

all: lib $(BIN)
lib: directory $(LIB)
directory:
	@mkdir -p bin/$(HOST)/$(PLATFORM)	
	@mkdir -p lib/$(HOST)/$(PLATFORM)		

$(BIN): $(BUILDDIR)/climdnssd.o  $(LIB)
	$(CC) $^ $(LIBRARY) $(CFLAGS) $(LDFLAGS) -o $@

$(LIB): $(OBJECTS)
	$(AR) -rcs $@ $^

$(BUILDDIR)/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

cleanlib:
	rm -f $(BUILDDIR)/*.o $(LIB) 

clean: cleanlib
	rm -f $(BIN)
