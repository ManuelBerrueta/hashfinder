# HashFinder

## Sample Use Cases:

### Find a file with a different hash from the input target file hash in a dir
```bash
hashfinder -diff -t tesfile.bin -dir ./testDir/
```

### Find a file with a matching hash to the has of the input target file in a dir
```bash
hashfinder -t tesfile.bin -dir ./testDir/
```

## TODO:
- Logging findings to a file
- Recursive directory search
- Hash as input string