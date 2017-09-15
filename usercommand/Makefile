FILES = $(wildcard *.cpp)
OBJECTS = $(subst .cpp,.o,$(FILES))

TARGET = $(TARGET_PATH)/firewall

CPP = g++
CPPFLAGS = -W -Wall -std=c++11

all:
	$(CPP) -c $(FILES) $(CPPFLAGS)
	$(CPP) -o $(TARGET) $(OBJECTS) $(CPPFLAGS)
clean:
	rm -rf $(OBJECTS)
	rm -rf $(TARGET)
