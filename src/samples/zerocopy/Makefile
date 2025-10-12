CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -pedantic
LDFLAGS ?=

TARGET  := capture_dmabuf
SRCS    := $(TARGET).c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
