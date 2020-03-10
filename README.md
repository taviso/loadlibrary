# Porting Windows Dynamic Link Libraries to Linux
## Introduction

This repository contains a library that allows native Linux programs to load
and call functions from a Windows DLL.

As a demonstration, I've ported Windows Defender to Linux.

```
$ ./mpclient eicar.com
main(): Scanning eicar.com...
EngineScanCallback(): Scanning input
EngineScanCallback(): Threat Virus:DOS/EICAR_Test_File identified.
```

### How does it work?

The `peloader` directory contains a custom PE/COFF loader derived from
ndiswrapper. The library will process the relocations and imports, then provide
a `dlopen`-like API. The code supports debugging with gdb (including symbols),
basic block coverage collection, and runtime hooking and patching.

![Is such a thing even possible?](https://media.giphy.com/media/2pDSW8QQU6jRe/giphy.gif)

### What works?

The intention is to allow scalable and efficient fuzzing of self-contained
Windows libraries on Linux. Good candidates might be video codecs,
decompression libraries, virus scanners, image decoders, and so on.

* C++ exception dispatch and unwinding.
* Loading additional symbols from IDA.
* Debugging with gdb (including symbols), breakpoints, stack traces, etc.
* Runtime hooking and patching.
* Support for ASAN and Valgrind to detect subtle memory corruption bugs.

If you need to add support for any external imports, writing stubs is usually
quick and easy.

### Why?

Distributed, scalable fuzzing on Windows can be challenging and inefficient.
This is especially true for endpoint security products, which use complex
interconnected components that span across kernel and user space. This
often requires spinning up an entire virtualized Windows environment to fuzz
them or collect coverage data.

This is less of a problem on Linux, and I've found that porting components of
Windows Antivirus products to Linux is often possible. This allows me to run
the code I’m testing in minimal containers with very little overhead, and
easily scale up testing.

This is just personal opinion, but I also think Linux has better tools. `¯\_(ツ)_/¯`

## Windows Defender

MsMpEng is the Malware Protection service that is enabled by default on Windows
8, 8.1, 10, Windows Server 2016, and so on. Additionally, Microsoft Security
Essentials, System Centre Endpoint Protection and various other Microsoft
security products share the same core engine.

The core component of MsMpEng responsible for scanning and analysis is called
mpengine. Mpengine is a vast and complex attack surface, comprising of handlers
for dozens of esoteric archive formats, executable packers, full system
emulators for various architectures and interpreters for various languages. All
of this code is accessible to remote attackers.

### Building

To build the test client, simply type `make`.

```
$ make
```

### Dependencies

*Note that the `.i686` or `:i386` suffixes are important, we need the 32bit libraries to use the 32bit dll.*

| Fedora / RedHat       | Ubuntu / Debian                     | Comment                      |
| --------------------- | ----------------------------------- |:---------------------------- |
| `glibc-devel.i686`    | `libc6-dev:i386` / `libc6-dev-i386` | Name varies with version.    |
| `libgcc.i686`         | `gcc-multilib`                      |                              |
| `readline-devel.i686` | `libreadline-dev:i386`              | Optional, used in mpscript.  |
| `cabextract`          | `cabextract`                        | Used to extract definitions. |

You will need to download the 32-bit antimalware update file from this page:

* https://www.microsoft.com/security/portal/definitions/adl.aspx#manual

This should be a direct link to the right file:

* https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86

This will download a file called `mpam-fe.exe`, which is a cabinet file that
can be extracted with `cabextract`. Extract the files into the `engine`
directory:

```
$ cabextract mpam-fe.exe
Extracting cabinet: mpam-fe.exe
  extracting MPSigStub.exe
  extracting mpavdlta.vdm
  extracting mpasdlta.vdm
  extracting mpavbase.vdm
  extracting mpasbase.vdm
  extracting mpengine.dll

All done, no errors.
```

If you want to know which version you got, try this:

```
$ exiftool mpengine.dll | grep 'Product Version Number'
Product Version Number          : 1.1.13701.0
```

### Running

The main mpengine loader is called `mpclient`, it accepts filenames to scan as
a parameter.

```
$ ./mpclient netsky.exe
main(): Scanning netsky.exe...
EngineScanCallback(): Scanning input
EngineScanCallback(): Threat Worm:Win32/Netsky.P@mm identified.
```

There are some other sample tools, `mpstreamfuzz` and `mpscript`.

### Debugging

If you want to debug a crash, single step through a routine or set breakpoints,
follow these examples. First, you need a map file from IDA.

Microsoft doesn't release public symbols for every build, and sometimes the
symbols lag behind for a few months after release. Make sure you're using an
mpengine version with public symbols available.

Use the following sample commandline to generate map and idb files.

```
> idaw -A -P+ -S"createmap.idc mpengine.map" mpengine.dll
```

If you generate the map files on Windows, you'll get CRLF line terminators, fix
them like this:

```
$ dos2unix mpengine.map
```

When you run mpclient under gdb, it will detect a debugger and print the
commands you need to enter to teach gdb about the symbols:

```
$ gdb -q ./mpclient
(gdb) r testfile.txt
Starting program: mpclient
main(): GDB: add-symbol-file engine/mpengine.dll 0xf6af4008+0x1000
main(): GDB: shell bash genmapsym.sh 0xf6af4008+0x1000 symbols_19009.o < mpengine.map
main(): GDB: add-symbol-file symbols_19009.o 0

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0804d213 in main (argc=1, argv=0xffffcc64, envp=0xffffcc6c) at mpclient.c:156
156	        __debugbreak();
(gdb)
```

If you enter the commands it shows into gdb, you will have symbols available.

> *Note that `genmapsym.sh` assumes you're using GNU awk.*

```
(gdb) add-symbol-file engine/mpengine.dll 0xf6af4008+0x1000
add symbol table from file "engine/mpengine.dll" at
	.text_addr = 0xf6af5008
Reading symbols from engine/mpengine.dll...done.
(gdb) shell bash genmapsym.sh 0xf6af4008+0x1000 symbols_19009.o < mpengine.map
(gdb) add-symbol-file symbols_19009.o 0
add symbol table from file "symbols_19009.o" at
	.text_addr = 0x0
Reading symbols from symbols_19009.o...done.
(gdb) p as3_parsemetadata_swf_vars_t
$1 = {void (void)} 0xf6feb842 <as3_parsemetadata_swf_vars_t>
```

Then you can continue, and it will run as normal.

```
(gdb) c
```

Breakpoints, watchpoints and backtraces all work as normal, although it may be
more reliable to use hardware breakpoints than software breakpoints.

To use hardware breakpoints in gdb, you just use `hb` or `hbreak` instead of
`break`. Note that you only get a limited number of hardware breakpoints.

```
(gdb) b as3_parsemethodinfo_swf_vars_t
Breakpoint 1 at 0xf6feb8da
(gdb) c
Continuing.
main(): Scanning test/input.swf...
EngineScanCallback(): Scanning input
Breakpoint 1, 0xf6feb8da in as3_parsemethodinfo_swf_vars_t ()
(gdb) bt
#0  0xf6feb8da in as3_parsemethodinfo_swf_vars_t ()
#1  0xf6dbad7f in SwfScanFunc ()
#2  0xf6d73ec3 in UfsScannerWrapper__ScanFile_scanresult_t ()
#3  0xf6d6c9e3 in UfsClientRequest__fscan_SCAN_REPLY ()
#4  0xf6d6a818 in UfsNode__ScanLoopHelper_wchar_t ()
#5  0xf6d6a626 in UfsNode__Analyze_UfsAnalyzeSetup ()
#6  0xf6d71f7f in UfsClientRequest__AnalyzeLeaf_wchar_t ()
#7  0xf6d71bb9 in UfsClientRequest__AnalyzePath_wchar_t ()
#8  0xf6dbbd88 in std___String_alloc_std___String_base_types_char_std__allocator_char______Myptr_void_ ()
#9  0xf6d75e72 in UfsCmdBase__ExecuteCmd__lambda_c80a88e180c1f4524a759d69aa15f87e____lambda_c80a88e180c1f4524a759d69aa15f87e__ ()
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
(gdb) x/3i $pc
=> 0xf6feb8da <as3_parsemethodinfo_swf_vars_t+7>:	lea    ebx,[edx+0x1c]
   0xf6feb8dd <as3_parsemethodinfo_swf_vars_t+10>:	push   esi
   0xf6feb8de <as3_parsemethodinfo_swf_vars_t+11>:	mov    edx,ebx
```

## What about Wine and Winelib?

This project does not replace Wine or Winelib.

Winelib is used to port Windows C++ projects to Linux, and Wine is
intended to run full Windows applications. This project is intended to allow
native Linux code to load simple Windows DLLs.

The closest analogy would be ndiswrapper but for userspace.

## Further Examples

* [avscript](https://github.com/taviso/avscript) - Loading another antivirus engine, demonstrates hooking and patching.

## License

GPL2

