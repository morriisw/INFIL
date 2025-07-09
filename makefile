CXX := g++
CXXFLAGS := -std=c++17 -I/opt/homebrew/include
LDFLAGS := -L/opt/homebrew/lib -ltins

SRC := infil.cpp scanner.cpp payload.cpp listener.cpp
OBJ := $(SRC:.cpp=.o)
TARGET := infil

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
