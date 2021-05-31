NAME=
AUTHOR=
VERSION=1.0
LINK=g++
LINKFLAGS= -Wall -g -std=c++11 -lpcap -lm -pthread #-L. -L/opt/local/lib
LINKLIBS=
LIBFLAGS=
CC=g++
CFLAGS= -Wall -g -std=c++11
ARCHIVE=ar
LEGITIMATE_OBJECTS=craft_packet_legitimate.o
ATTACK_OBJECTS=craft_packet_attack.o
TRACE_DRIVEN_OBJECTS=trace_driven_traffic.o
TARGETS=craft_packet_legitimate craft_packet_attack trace_driven_traffic
TEST_TARGETS=

all: $(TARGETS)

test: $(TEST_TARGETS)

craft_packet_legitimate: $(LEGITIMATE_OBJECTS)
	$(LINK) -o craft_packet_legitimate $(LEGITIMATE_OBJECTS) $(LINKFLAGS)

craft_packet_attack: $(ATTACK_OBJECTS)
	$(LINK) -o craft_packet_attack $(ATTACK_OBJECTS) $(LINKFLAGS)

trace_driven_traffic: $(TRACE_DRIVEN_OBJECTS)
	$(LINK) -o trace_driven_traffic $(TRACE_DRIVEN_OBJECTS) $(LINKFLAGS)

craft_packet_legitimate.o: craft_packet_legitimate.cpp
	$(CC) -c $(CFLAGS) craft_packet_legitimate.cpp

craft_packet_attack.o: craft_packet_attack.cpp
	$(CC) -c $(CFLAGS) craft_packet_attack.cpp

trace_driven_traffic.o: trace_driven_traffic.cpp
	$(CC) -c $(CFLAGS) trace_driven_traffic.cpp

clean:
	rm *.o craft_packet_legitimate craft_packet_attack trace_driven_traffic
