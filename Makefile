CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -pthread
LDLIBS ?= -lcrypto

ufcp: src/ufcp.cpp src/transport.hpp src/wire.hpp src/file_io.hpp src/congestion.hpp src/crypto.hpp src/session_io.hpp src/remote.hpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

transport-test: tests/transport.cpp src/transport.hpp src/wire.hpp src/file_io.hpp src/crypto.hpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

controller-test: tests/controller.cpp src/congestion.hpp src/transport.hpp
	$(CXX) $(CXXFLAGS) $< -o $@

session-test: tests/session.cpp src/crypto.hpp src/session_io.hpp src/wire.hpp src/transport.hpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

test: ufcp transport-test controller-test session-test
	./transport-test
	./controller-test
	./session-test
	python3 tests/integration.py ./ufcp
	python3 tests/remote.py ./ufcp

ssh-test: ufcp
	python3 tests/ssh.py ./ufcp

netns-test: ufcp
	python3 tests/netns.py ./ufcp

.PHONY: test ssh-test netns-test
