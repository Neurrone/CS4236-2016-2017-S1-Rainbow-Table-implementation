module invert;
import common;
// reads a rainbow table  from "rainbow" in the current directory

import std.typecons : Tuple;
alias Result = Tuple!(bool, "success", Plaintext, "plaintext");
size_t nSha1Calls = 0;

void main() {
	import std.datetime : MonoTime;
	import std.stdio : readln, writeln, writefln;
	import std.range : iota;
	
	auto tables = rebuildTable();
	
	size_t found = 0;
	nSha1Calls = 0;
	foreach (i; iota(5000)) {
		auto digest = parseLine(readln());
		auto result =  preimage(digest, tables, chainSize);
		if (result.success) {
			import std.digest.digest : toHexString;
			writeln(toHexString(result.plaintext));
			++found;
		}
		else
			writeln(0);
	}
	writeln("Found ", found, " hashes, accuracy C is ", found/5000.0 * 100, "%.");
	auto speedupFactor = (5000.0 * 2^^(23)) / nSha1Calls;
	long sizeInBytes = nTables * chains * 3;
	long sizeSquared = sizeInBytes^^2;
	real temp = (2^^30) * speedupFactor;
	temp /= sizeSquared;
	auto score = 18 - 7 * (1.1 - temp);
	if (score > 18) score = 18;
	writeln("Table size = ", sizeInBytes, " bytes.");
	writeln("Sha1 was called ", nSha1Calls, " times.");
	writeln("Speedup factor f = ", speedupFactor, ", score = ", score);
}

// parses the line read from stdin to read the sha1 digest
pure Digest parseLine(string line) {
	Digest d;
	import std.range, std.algorithm : filter, copy;
	import std.ascii;
	import std.array : appender;
	import std.conv;
	
	auto app = appender!(char[]);
	filter!(c => isHexDigit(c))(line).copy(app);
	foreach (i; iota(0, app.data.length, 2)) {
		d[i/2] = to!ubyte(app.data[i..i+2], 16);
	}
	return d;
}

unittest {
	import std.digest.sha;
	auto test = "BBA61AD5  5E501487  10E4E66D  24F462D9  19888F44";
	auto digest = parseLine(test);
	auto expected = "BBA61AD55E50148710E4E66D24F462D919888F44";
	assert(toHexString(digest) == expected);
	assert(digest == parseLine(expected)); // it correctly ignores  non-hex characters
}

// reconstructs the full rainbow table from rainbow
Table[] rebuildTable() {
	import std.stdio, std.range : iota;
	File file = File("rainbow", "rb");
	Table[] tables = new Table[nTables];
	
	foreach (i; iota(nTables)) {
		auto chainStarts = generateRandomPlaintexts(i);
		foreach (j; iota(chains)) {
			Plaintext end;
			file.rawRead(end);
			import std.algorithm.searching, std.algorithm.comparison : equal;
			
			auto isEndInTable = end in tables[i];
			if (!isEndInTable || find(tables[i][end], chainStarts[j]).length == 0)
				tables[i][end] ~= chainStarts[j];
		}
		tables[i].rehash;
	}
	
	return tables;
}

/// attempt to find the preimage of the supplied hash
Result preimage(Digest digest, Table[] tables, int chainSize) {
	import std.stdio, std.range : iota;
	Result res;
	foreach (i; iota(1, chainSize+1)) {
		foreach(j; iota(tables.length)) {
			auto end = extendChain(digest, i, chainSize, j);
			
			if(auto ptr = end in tables[j]) {
				foreach (start; tables[j][end]) {
				res = findPreimageInChain(digest, start, chainSize-i+1, j);
				if (res.success) return res;
				}
			}
		}
	}
	res.success = false;
	return res;
}

// finds the preimage of a digest in a chain, where chainSize is the number of times that sha1 should be applied
Result findPreimageInChain(Digest hash, Plaintext start, int chainSize, int tableIndex) {
	Result res;
	res.success = false;
	auto p = start;
	Digest d;
	import std.range : iota;
	foreach (i; iota(0, chainSize)) {
		d = sha1(p);
		
		if (d == hash) {
			res.success = true;
			res.plaintext = p;
			return res;
		}
		p = reduce(i, tableIndex, d);
	}
	return res;
}

// extends the chain
// length is the number of applications of the reduction function that should be applied before reaching the end
Plaintext extendChain(Digest d, int length, int chainSize, int tableIndex) {
	import std.range : iota;
	Plaintext p = void;
	foreach(i; iota(chainSize - length, chainSize)) {
		p = reduce(i, tableIndex, d);
		if (i < chainSize - 1)
			d = sha1(reduce(i, tableIndex, d));
	}
	return p;
}

unittest {
	Plaintext[4] p;
	Digest[3] h;
	import std.digest.sha, std.range : iota;
	p[0] = [175, 27, 65];
	h[0] = sha1Of(p[0]);
	
	foreach (i; iota(1, 3)) {
		p[i] = reduce(i-1, 0, h[i-1]);
		h[i] = sha1Of(p[i]);
	}
	p[3] = reduce(2, 0, h[2]);
	auto chainSize = 3;
	assert(extendChain(h[2], 1, chainSize, 0) == p[3]);
	assert(extendChain(h[1], 2, chainSize, 0) == p[3]);
	assert(extendChain(h[0], 3, chainSize, 0) == p[3]);
	// is the preimage correctly found if it exists in the chain?
	foreach (i; iota(chainSize)) {
		auto res = findPreimageInChain(h[i], p[0], chainSize, 0);
		assert(res.success && res.plaintext == p[i]);
	}
	Table[1] tables;
	
	tables[0][p[3]] = [p[0]];
	foreach (i; iota(3)) {
		auto res =  preimage(h[i],  tables, chainSize);
		assert(res.success && res.plaintext == p[i]);
	}
}

// wrapper around the sha1 function in the standard library that increments nSha1Calls
Digest sha1(Plaintext p) {
	import std.digest.sha;
	++nSha1Calls;
	return sha1Of(p);
}
