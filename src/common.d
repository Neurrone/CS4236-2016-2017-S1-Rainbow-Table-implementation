module common;
// contains code shared between GenRainbow.d and invert.d
public:
alias Digest = ubyte[20];
alias Plaintext = ubyte[3];
alias Table = Plaintext[][Plaintext];

// for the RNG
immutable uint[4] seeds = [562852006, 6975283, 255927310, 16974802];
uint[4] offsets = [255927310, 110318571, 17993895, 16974802];

immutable uint nPasswords = 2 ^^ 24; // |P|

immutable uint nTables = 3;
immutable uint chains = 70000;
immutable uint chainSize = 220;
/*
Plaintext[] generateRandomPlaintexts(int tableIndex) {
	Plaintext[] p = new Plaintext[chains];
	import std.random;
	Mt19937 rng;
	rng.seed(seeds[tableIndex]);
	import std.range : iota;
	foreach (i; iota(chains)) {
		p[i] = intToPlaintext(rng.front());
		rng.popFront();
	}
	
	return p;
}
*/

Plaintext[] generateRandomPlaintexts(int tableIndex) {
	Plaintext[] p = new Plaintext[chains];
	uint partitionSize = nPasswords / nTables;
	uint n = tableIndex * partitionSize;
	uint delta = nPasswords / (chains * nTables);
	
	import std.range : iota;
	foreach (i; iota(chains)) {
		p[i] = intToPlaintext(n);
		n += delta;
	}
	
	return p;
}

// converts an integer into a valid plaintext by taking the last 24 bits of the integer as the 3 bytes for plaintext
pure Plaintext intToPlaintext(uint n) {
	import std.range : iota;
	Plaintext p = void;
	foreach (byteToGet; iota(3))
		p[2-byteToGet] = (n >> (8*byteToGet)) & 0xff; // get the first 3 bytes
		
	return p;
}

unittest {
	auto p = intToPlaintext(0x0036d7fb);
	Plaintext expected = [0x36, 0xd7, 0xfb];
	assert(p == expected);
}

// reduce function r_{i}
pure Plaintext reduce (int i, int table, Digest digest) {
	import std.range : iota;
	uint n;
	if (table == 0)
		n = digest[0] * 2^^16 + digest[1] * 2^^8 + digest[2];
	else if (table == 1)
		n = digest[3] * 2^^16 + digest[4] * 2^^8 + digest[5];
	else if (table == 2)
		n = digest[6] * 2^^16 + digest[7] * 2^^8 + digest[8];
	else if (table == 3)
		n = digest[9] * 2^^16 + digest[10] * 2^^8 + digest[11];
	else if (table == 4)
		n = digest[12] * 2^^16 + digest[13] * 2^^8 + digest[14];
	else	
		n = digest[15] * 2^^16 + digest[16] * 2^^8 + digest[17];
	
	n += i;
	return intToPlaintext(n);
}

unittest {
	Digest d;
	d[0] = 0b1100;
	d[1] = 0b1001;
	d[2] = 0b0100;
	assert(reduce (0, 0, d) == d[0..3]);
	assert(reduce (10, 0, d) == [d[0], d[1], d[2] + 10]);
	Digest d2;
	d2[0] = 0xff;
	d2[1] = 0xff;
	d2[2] = 0xff;
	assert(reduce (3, 0, d2) == [0x0, 0x0, 0x2]);
}

// this RNG generates a sequence of 2^{32} nonrepeating values before repeating
// obtained from http://preshing.com/20121224/how-to-generate-a-sequence-of-unique-random-integers/
struct Rng {
private:
    uint index;
    uint intermediateOffset;
    static immutable uint prime = 4294967291;

    static uint permuteQPR(uint x) {
        if (x >= prime)
            return x;  // The 5 integers out of range are mapped to themselves.
        uint residue = (cast(ulong) x * x) % prime;
        return (x <= prime / 2) ? residue : prime - residue;
    }

public:
    this(uint seedBase, uint seedOffset) {
        index = permuteQPR(permuteQPR(seedBase) + 0x682f0161);
        intermediateOffset = permuteQPR(permuteQPR(seedOffset) + 0x46790905);
    }

    uint next() {
        return permuteQPR((permuteQPR(index++) + intermediateOffset) ^ 0x5bf03635);
    }
}
