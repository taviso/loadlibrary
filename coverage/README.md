# Collecting Basic Block Coverage Data
## Introduction

This directory contains a simple pintool for collecting code coverage data, and
tools and scripts for processing that data. These tools can assist with corpus
distillation and anti-corpus auditing.

In it's simplest mode of operation, this tool simply creates a list of basic
blocks executed from the loaded DLL.

```
$ ./coverage/pin -t coverage/deepcover.so -- ./mpclient eicar.com
main(): Scanning eicar.com...
EngineScanCallback(): Scanning input
EngineScanCallback(): Threat Virus:DOS/EICAR_Test_File identified.


----- COVERAGE ANALYSIS -----
         58590 Unique Instructions Executed
         10271 Unique Basic Blocks Executed
       3193230 Total Instructions Executed
        590362 Total Basic Blocks Executed
    Hottest Basic Block (0x00000000003918e7)
             11731 Executes
                 3 Instructions

$ wc -l coverage.txt
10271 coverage.txt
```

However, with some simple processing, we can produce annotated IDBs or create a
distilled corpus for fuzzing.

![Annotated IDB](https://raw.githubusercontent.com/taviso/loadlibrary/master/doc/annotatedidb.png)

## Build

Download the latest pintool for gcc from the pintool download page, and extract
it in the `coverage` directory.

* https://software.intel.com/en-us/articles/pintool-downloads

```
$ tar -zxvf pin-3.2-81205-gcc-linux.tar.gz
```

Now type `make`, and the tool should build.

If you want to do corpus distillation, you can also build the tool
`coverage_parse_min`, note that it requires the `glib-2.0` development package.

```
$ make coverage_parse_min
```

## Running

To create a list of all the basic blocks executed, simply do this:

```
$ ./coverage/pin -t coverage/deepcover.so -- ./mpclient eicar.com
main(): Scanning eicar.com...
EngineScanCallback(): Scanning input
EngineScanCallback(): Threat Virus:DOS/EICAR_Test_File identified.


----- COVERAGE ANALYSIS -----
         58590 Unique Instructions Executed
         10271 Unique Basic Blocks Executed
       3193230 Total Instructions Executed
        590362 Total Basic Blocks Executed
    Hottest Basic Block (0x00000000003918e7)
             11731 Executes
                 3 Instructions
```

The report is called `coverage.txt` by default, but you can override it by
setting the `COVERAGE_REPORT_FILE` environment variable.

If you have a directory of testcases you would like to generate coverage
reports for, you can use `xargs` like this:

```
$ ls samples
sample1.exe
sample2.exe
sample3.zip
...
$ find samples -type f | xargs -t -I{} -P8 -n1 env COVERAGE_REPORT_FILE={}.txt ./coverage/pin -t coverage/deepcover.so -- ./mpclient {}
```

> The `-P` parameter to xargs specifies how many processes you can run in
> parallel. In general, set this to the number of cores you have available.

### Corpus Distillation

If you have a lot of inputs and want to find the minimal set cover for fuzzing,
first generate coverage reports for all your inputs.

```
$ find samples -type f | xargs -t -I{} -P8 -n1 env COVERAGE_REPORT_FILE={}.txt ./coverage/pin -t coverage/deepcover.so -- ./mpclient {}
```

Now build the tool `coverage_parse_min`

```
$ make -C coverage coverage_parse_min
```

Now you can find a distilled corpus like this:

```
$ grep -H ^ samples/*.txt | awk -F: '{print $2FS$1}' | ./coverage_parse_min | cut -d: -f2 | sort -u
```

### Anticorpus Auditing

The "anticorpus" auditing technique is a simple idea, but nevertheless
experience suggests it can be effective on fuzz-clean software. The idea is to
build coverage data, then hilight codepaths that fuzzing isn't reaching.

A simple script to produce annotated idbs is included, generate coverage
reports for your inputs as above.

```
$ grep -H ^ *.txt | awk -F: '{print $2FS$1}' | ./coverage_parse_min | sed -e 's#:.*/#:#g' -e 's/.txt$//' > minimal.txt
$ bash genidc.sh minimal.txt > coverage.idc
```

Now you can load this file in IDA with `File->Script File...`.

## Notes

* The pintool only starts collecting coverage data once you've called `InstrumentationCallback()`.
* You can blacklist blocks you don't want instrumented by listing them in `blacklist.h`.

## License

GPL2

