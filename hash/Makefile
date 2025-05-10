.PHONY: all clean format

PROJECT = hash_md5

CXX=g++
CXXFLAGS=-O2 -Wall -DNDEBUG -std=c++17
LDFLAGS= -lcrypto++

SOURCES := $(wildcard *.cpp)
HEADERS := $(wildcard *.h)
OBJECTS := $(SOURCES:%.cpp=%.o)

all : $(PROJECT)

$(PROJECT) : $(OBJECTS)
	$(CXX) $^ $(LDFLAGS) -o $@

%.o : %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(OBJECTS) : $(HEADERS)

format:
	astyle *.cpp *.h
	
clean:
	rm -f $(PROJECT) *.o *.orig
