CXXSRCS=main.cc watcher.cc graph.cc load_ldconfig.cc utils.cc communicate.cc
OBJS=$(CXXSRCS:.cc=.o)
LIBS=-lcurl -lcrypto -lssl
TARGET=watcher

all: $(TARGET)

clean:
	-rm $(TARGET) $(OBJS)

$(TARGET): $(OBJS)
	$(CXX) -g -O0 -o $(TARGET) $(OBJS) $(LIBS)

.cc.o:
	$(CXX) -g -O0 -c $< -o $@

