ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is undefined. Set it to the PS5 payload SDK root.)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

ELF := permission_broker.elf
LIBHIJACKER_DIR ?= extern/libhijacker

ifeq ($(wildcard $(LIBHIJACKER_DIR)/libhijacker.a),)
$(error Missing $(LIBHIJACKER_DIR)/libhijacker.a. Run ./scripts/prepare-deps.sh first.)
endif

CXXFLAGS += -std=c++20 -Wall -Wextra -O2 -fno-rtti -fno-exceptions
CXXFLAGS += -I$(LIBHIJACKER_DIR)/include -Iinclude
LDFLAGS += -L$(LIBHIJACKER_DIR)
LDLIBS += -lhijacker -lkernel_sys -lSceNotification

OBJS := source/main.o source/offsets_v940.o

all: $(ELF)

source/%.o: source/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(ELF): $(OBJS) $(LIBHIJACKER_DIR)/libhijacker.a
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(ELF) $(OBJS)

.PHONY: all clean
