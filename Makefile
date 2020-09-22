all : pcap-test

pcap-test : prints.o main.o
	g++ -o pcap-test prints.o main.o -l pcap

prints.o : prints.cpp pcap-test.h
	g++ -c -o prints.o prints.cpp -l pcap

main.o : main.cpp pcap-test.h
	g++ -c -o main.o main.cpp -l pcap

clean:
	rm -f pcap-test *.o


