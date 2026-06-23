CC := gcc
CFLAGS := -O2 -Wall -Wextra -I ../.. -I ../../include
LDFLAGS := -lrt

SRCS := $(wildcard *.c)
TARGETS := $(SRCS:.c=)

.PHONY: all clean test

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test: $(TARGETS)
	@for t in $(TARGETS); do \
		echo "Running $$t..."; \
		./$$t; \
	done

clean:
	rm -f $(TARGETS)
