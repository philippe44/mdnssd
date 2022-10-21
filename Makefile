ifeq ($(CC),cc)
CC=$(lastword $(subst /, ,$(shell readlink -f `which cc`)))
endif

PLATFORM ?= $(firstword $(subst -, ,$(CC)))
HOST ?= $(word 2, $(subst -, ,$(CC)))

SRC 		= .
BIN			= bin/climdnssd-$(HOST)-$(PLATFORM)
LIB			= lib/$(HOST)/$(PLATFORM)/libmdnssd.a
BUILDDIR	= build/$(HOST)/$(PLATFORM)

CFLAGS  += -Wall -Wno-stringop-truncation -fPIC -ggdb -O2 $(DEFINES) -fdata-sections -ffunction-sections 
LDFLAGS += -s

vpath %.c $(SRC)

INCLUDE = -I$(SRC) 

SOURCES =  mdnssd.c
	
OBJECTS = $(SOURCES:%.c=$(BUILDDIR)/%.o) 

all: lib $(BIN)
lib: directory $(LIB)
directory:
	@mkdir -p bin
	@mkdir -p lib/$(HOST)/$(PLATFORM)	
	@mkdir -p $(BUILDDIR)/lib

$(BIN): $(BUILDDIR)/climdnssd.o  $(LIB)
	$(CC) $^ $(LIBRARY) $(LDFLAGS) -o $@

$(LIB): $(OBJECTS)
	$(AR) rcs $@ $^

$(BUILDDIR)/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

cleanlib:
	rm -f $(BUILDDIR)/*.o $(LIB) 

clean: cleanlib
	rm -f $(BIN)
