# Assatulla Dias 3BIT 
# ISA project 2023/2024
# Makefile for my cpp program

CXX = g++
CXXFLAGS = -Wall -Wextra -g

LDFLAGS = -lpcap

TARGET = dhcp-stats

SOURCES = dhcp-stats.cpp

OBJECT = $(SOURCES:.cpp=.o)

.PHONY: all clean tar

all: $(TARGET)

$(TARGET): $(OBJECT)
	$(CXX) $(CXXFLAGS)  -o $@ $(OBJECT) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ 

clean:
	rm -f $(TARGET) $(OBJECT)

tar: 
	tar -cf xassat00.tar *.cpp Makefile README.md