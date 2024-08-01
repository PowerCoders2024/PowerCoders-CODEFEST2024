CXX = g++
CXXFLAGS = --optimize=fast -std=c++20 -lwolfssl
TARGET = main.out

SRCS = $(wildcard *.cpp */*.cpp)
HEADERS = $(wildcard *.h */*.h)
OBJS = $(SRCS:.cpp=.o)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(CXXFLAGS)

%.o: %.cpp $(HEADERS)
	$(CXX) -c $< -o $@ $(CXXFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJS)