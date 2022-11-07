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

SRC        = .
CORE       = bin/climdnssd-$(HOST)
BUILDDIR   = $(dir $(CORE))$(HOST)/$(PLATFORM)
LIB		   = lib/$(HOST)/$(PLATFORM)/libmdnssd.a
EXECUTABLE = $(CORE)-$(PLATFORM)

CFLAGS  += -Wall -fPIC -ggdb -O2 $(DEFINES) -fdata-sections -ffunction-sections 

vpath %.c $(SRC)

INCLUDE = -I$(SRC) 

SOURCES =  mdnssd.c
	
OBJECTS = $(SOURCES:%.c=$(BUILDDIR)/%.o) 

all: lib $(EXECUTABLE)
lib: directory $(LIB)
directory:
	@mkdir -p lib/$(HOST)/$(PLATFORM)	
	@mkdir -p $(BUILDDIR)		

$(EXECUTABLE): $(BUILDDIR)/climdnssd.o  $(LIB)
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@
ifeq ($(HOST),macos)
	rm -f $(CORE)
	lipo -create -output $(CORE) $$(ls $(CORE)* | grep -v '\-static')
endif

$(LIB): $(OBJECTS)
	$(AR) -rcs $@ $^

$(BUILDDIR)/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

cleanlib:
	rm -f $(BUILDDIR)/*.o $(LIB) 

clean: cleanlib
	rm -f $(EXECUTABLE) $(CORE)
