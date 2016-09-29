module genrainbow;
import common;

void main() {
	import std.stdio, std.datetime : MonoTime;
	import std.range : iota;
	auto before = MonoTime.currTime;
	File file = File("rainbow", "wb");
	foreach (i; iota(nTables)) {
		auto ends = generateChainEnds(i);
		
		foreach (end; ends) {
			file.rawWrite(end);
		}
	}
	
	writeln(MonoTime.currTime - before);
}

// generate the end of the chains corresponding to the random plaintexts
Plaintext[] generateChainEnds(int tableIndex) {
	import std.parallelism, std.range : iota;
	Plaintext[] ends = new Plaintext[chains];
	auto p = generateRandomPlaintexts(tableIndex);
	
	foreach (i; parallel(iota(chains))) {
		ends[i] = createChainWithEndingPlaintext(p[i], tableIndex);
	}
	return ends;
}

pure Plaintext createChainWithEndingPlaintext(Plaintext plaintext, int tableIndex) {
	import std.digest.sha, std.range : iota;
	auto hash = sha1Of(plaintext);
	plaintext = reduce(0, tableIndex, hash);
	foreach (i; iota(1, chainSize)) {
		hash = sha1Of(plaintext);
		plaintext = reduce(i, tableIndex, hash);
	}
	
	return plaintext;
}
