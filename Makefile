all:
	$(CXX) -O2 -Wall $(CXXFLAGS) -I. contracthashtool.c stolen.cpp uint256.cpp crypto/ripemd160.cpp crypto/sha2.cpp -o contracthashtool -lsecp256k1
