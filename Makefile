TARGET = 1m-block

all: $(TARGET)

$(TARGET): nfqnl_test.cpp ip.h
	g++ -o $(TARGET) nfqnl_test.cpp -lnetfilter_queue

clean:
	rm -f $(TARGET)
