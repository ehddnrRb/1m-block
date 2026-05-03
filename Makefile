TARGET = 1m-block

all: $(TARGET)

$(TARGET): 1m-block.cpp ip.h
	g++ -o $(TARGET) 1m-block.cpp -lnetfilter_queue

clean:
	rm -f $(TARGET)
