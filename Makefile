# on a mac need to set PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# the code *requires* C++ 17 or later
# changed optimization to 00 for debugging - from 02
CXX=clang++
CXXFLAGS = -g -O0 -I. -Wall -std=c++17
CXXFLAGS += $(shell pkg-config --cflags libndn-ind)
PROTOC=protoc
LIBS = $(shell pkg-config --libs libndn-ind)
HDRS = CRshim.hpp syncps/syncps.hpp syncps/iblt.hpp
OBJS = syncps/syncps-content.pb.o
DEPS = $(HDRS) $(OBJS)
BINS = getStatus nod getBH
JUNK = 
PROBEOBJS = formats/face-status.pb.o formats/forwarder-status.pb.o \
            formats/rib-entry.pb.o
PROBEDEPS = probes.hpp $(PROBEOBJS)

# OS dependent definitions
ifeq ($(shell uname -s),Darwin)
LIBS += -lboost_iostreams-mt -lboost_chrono-mt -lprotobuf -llog4cxx
JUNK += $(addsuffix .dSYM,$(BINS))
else
LIBS += -lboost_iostreams -lboost_chrono -lprotobuf -llog4cxx -lpthread
endif

all: $(BINS)

.PHONY: clean distclean tags

getStatus: getStatus.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(OBJS) $(LIBS)

getBH: getBH.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(OBJS) $(LIBS)

nod: nod.cpp $(PROBEDEPS) $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(PROBEOBJS) $(OBJS) $(LIBS)

%.pb.cc: %.proto
	$(PROTOC) --proto_path=$(dir $<) --cpp_out=$(dir $<) $<

clean:
	rm -f $(BINS) $(OBJS) syncps/syncps-content.pb.* formats/*.pb.*

distclean: clean
	rm -rf $(JUNK)
