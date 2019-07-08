# Change to executable name.
PROG := server

# Add whatever compiler flags you want.

CC = gcc
CFLAGS += -Wall -Wextra -Werror -pthread

# You MUST keep this for auto-dependency generation.

# Can change depending on project
LDLIBS := 

# Not sure when you will really need this. Can leave blank usually.
LDFLAGS :=

# Change 'src/' to where ever you hold src files relative to Makefile.
SRCS := $(wildcard ./src/*.c)

# Generate .o and .d filenames for each .cpp file.
# Doesn't generate the ACTUAL files (compiler does).
# Just generates the lists.
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)

# GNUMake feature, in case you have files called 'all' or 'clean'.
.PHONY: all clean

# Called when you run 'make'. This calls the line below.
all: $(PROG)

# Calls the compiler with flags to link all object files together.
$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(LDLIBS) $(OBJS) -o $(PROG)

# Includes the dependency lists (.d files).
-include $(DEPS)

# Removes exectuable, object files, and dependency files.
clean:
	rm -f $(PROG)
	rm -f $(DEPS) $(OBJS)
	rm -f app.xml

run: all
	./$(PROG)
