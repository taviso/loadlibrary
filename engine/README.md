# mpengine

Download the 32-bit manual antimalware update file from this page:

    * https://www.microsoft.com/security/portal/definitions/adl.aspx#manual

This should be a direct link:

    * http://go.microsoft.com/fwlink/?LinkID=121721&arch=x86

This will download a file called mpam-fe.exe, which is a self-extracting
cabinet file that can be extracted with cabextract. Extract the file into the
engine subdirectory:

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
$ exiftool mpengine.dll  | grep 'Product Version Number'
Product Version Number          : 1.1.13701.0
```
