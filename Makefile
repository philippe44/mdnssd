ifeq ($(CC),cc)
CC=$(lastword $(subst /, ,$(shell readlink -f `which cc`)))
endif

PLATFORM ?= $(firstword $(subst -, ,$(CC)))
HOST ?= $(word 2, $(subst -, ,$(CC)))

SRC 		= .
BIN			= bin/mdnssd-$(PLATFORM)
LIB			= lib/$(HOST)/$(PLATFORM)/libmdnssd.a
BUILDDIR	= build/$(PLATFORM)


CFLAGS  += -Wall -Wno-stringop-truncation -Wno-format-truncation -fPIC -ggdb -O2 $(OPTS) $(INCLUDE) $(DEFINES) -fdata-sections -ffunction-sections 
LDFLAGS += -s

vpath %.c $(SRC)

INCLUDE = -I$(SRC) 

SOURCES = mdnssd-core.c mdnssd.c
		
OBJECTS = $(patsubst %.c,$(BUILDDIR)/%.o,$(SOURCES)) 

all: directory $(BIN) $(LIB)

$(BIN): $(OBJECTS)
	$(CC) $(OBJECTS) $(LIBRARY) $(LDFLAGS) -o $@

$(LIB): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS) 

directory:
	@mkdir -p bin
	@mkdir -p lib/$(HOST)/$(PLATFORM)	
	@mkdir -p $(BUILDDIR)/lib

$(BUILDDIR)/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

clean:
	rm -f $(OBJECTS) $(LIBOBJECTS) $(BIN) $(LIB)
