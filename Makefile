LDLIBS=-lpcap

all: deauth-attack

deauth-attack: main.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f deauth-attack *.o