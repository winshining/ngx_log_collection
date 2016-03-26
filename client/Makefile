CXX := g++
CFLAGS = -g -Wall
EXEC := log_collection_client
INC_DIR = $(PWD)/include
SRC_DIR = $(PWD)/src
STD_LIB = pthread

SRC = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(addsuffix .o, $(basename $(SRC)))

all: $(EXEC)
$(EXEC): $(OBJS)
	$(CXX) $(CFLAGS) -o $(EXEC) $(OBJS) -l$(STD_LIB)

%.o : %.cpp
	-@echo "now compling $<..."
	$(CXX) $(CFLAGS) -o $@ -c $< -I$(INC_DIR)

.PHONY: all clean
clean:
	-@echo "cleaning..."
	-@rm -rf $(OBJS) $(EXEC)
	-@echo "clean done!"

