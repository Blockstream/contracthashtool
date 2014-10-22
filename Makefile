all:
	$(CXX) -O2 -Wall $(CXXFLAGS) -lsecp256k1 -I. contracthashtool.c stolen.cpp uint256.cpp crypto/ripemd160.cpp crypto/sha2.cpp -o contracthashtool
