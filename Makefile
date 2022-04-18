LIBNFC_DIR = .
CFLAGS = -g -O2 -Wall -pedantic -Wextra -std=c99 -Du_int8_t=uint8_t -Du_int16_t=uint16_t -I/usr/include/python3.7/
LDFLAGS =-lpython3.7m -lusb --shared
LIBNFC_CFLAGS = -I$(LIBNFC_DIR)/libnfc -I$(LIBNFC_DIR)/include -I$(LIBNFC_DIR)/utils
TARGET = nfc4py.so
CC = gcc
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
EXTERN_OBJS = $(wildcard $(LIBNFC_DIR)/utils/mifare.o $(LIBNFC_DIR)/utils/nfc-utils.o $(LIBNFC_DIR)/libnfc/*.o $(LIBNFC_DIR)/libnfc/drivers/*.o $(LIBNFC_DIR)/libnfc/buses/*.o $(LIBNFC_DIR)/libnfc/chips/*.o)

all: $(TARGET)

$(OBJS) : %.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(LIBNFC_CFLAGS)

$(TARGET) : $(OBJS) $(EXTERN_OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(EXTERN_OBJS) $(LDFLAGS)

clean:
	rm $(TARGET) $(OBJS)
