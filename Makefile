ifeq ($(OS),Windows_NT)
OBJECTS += gerror.o
OBJECTS += $(patsubst %.c,%.o,$(wildcard src/windows/*.c))
else
OBJECTS += $(patsubst %.c,%.o,$(wildcard src/linux/*.c))
endif

CPPFLAGS += -Iinclude -I../
CFLAGS += -fPIC

LDFLAGS += -L../gimxlog
LDLIBS += -lgimxlog

include Makedefs

ifeq ($(OS),Windows_NT)
gerror.o: ../gimxcommon/src/windows/gerror.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
endif
