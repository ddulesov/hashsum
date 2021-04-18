hashsum is tool  that calculates and verifies file hashes. It's used like a similar sha1sum, md5sum but use fast gost-34.11-2012 and blake cryptographic hash functions.  
It is commonly used to verify the integrity of files. 
For file checking hashsum use all available CPU cores  achieving 4-6 x speedup compared to single-threaded approach.
On the x86-64 [Blake3](https://github.com/BLAKE3-team/BLAKE3) hash calculation use SIMD available for this CPU (SSE2, SSE4.1 AVX2 AVX512) 

Support Linux, FreeBSD, Microsoft Windows

## Usage
To create a file with an gost-34.11-2012 hash in it, if one is not provided:
```
$ hashsum -t g256 filename [filename2] ... > GOSTSUM.check
$ hashsum -t g256 * > GOSTSUM.check
```
Using Blake3 
```
$ hashsum -t b3 filename [filename2] ... > BLAKE3SUM.check
```

calculate hash from standard input
```
$ hashsum -t b3 - < input_file
```

## Verification
```
$ hashsum  -t g256 -c GOSTSUM.check
```
"-t g256" parameter is omitted as it is default hash type 


"-v" verbose output contain each verified file and hash validation status
```
$ hashsum  -t g256 -c GOSTSUM.check
```

Blake3 hash verification
```
$ hashsum  -t b3 -c BLAKE3SUM.check
```

## Returns
On success returns 0 
Returns 1 if any checked file failed hash test.
Returns 2 if the check file has incorrectly formatted lines or any of the verified file doesn't exist 