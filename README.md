# **HashFinder**
HashFinder finds if a file in a directory and subdirectories full of the same file is different (modified) by using the targetfile hash or hash as input string.               *
Also will help you find a file matching a hash in a directory and subdirectories.
This is useful for forensics and possibly finding interesting files like malware or other artifacts.

## Sample Use Cases:

### Find a file with a different hash from the input target file hash in a dir
```bash
hashfinder -diff -t tesfile.bin -dir testDir
```

### Find a file with a matching hash to the hash of the input target file in a dir
```bash
hashfinder -t tesfile.bin -dir testDir
```

### Find a file with a different hash from given input string hash in a dir
```bash
hashfinder -diff -i inputHashString -dir testDir
```

### Find a file with a matching hash to the input string hash in a dir
```bash
hashfinder -t tesfile.bin -i inputHashString -dir testDir
```
### Find a file with a matching hash to the input string hash in a dir
```bash
hashfinder -t tesfile.bin -i inputHashString -dir testDir
```
*HashFinder default hashing is sha2. Specify hash with -m cryptoType*

## TODO:
- Logging findings to a file