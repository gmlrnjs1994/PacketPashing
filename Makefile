
all : overwatcher

overwatcher : pcap.o
	gcc -o overwatcher pcap.o -lpcap

pcap.o : pcap.c
	gcc -c -o pcap.o pcap.c -lpcap

clean :
	rm *.o overwatcher
