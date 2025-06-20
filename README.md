Checksec-anywhere - A platform-agnostic checksec tool for Elf, Pe, and Mach-O binaries in your browser.

### Build/Install
```
git clone https://github.com/trailofbits/checksec-anywhere.git
cd checksec-anywhere && make all
make local_instance //run the checksec tool locally (python3 required)
```

### Run outside of browser
Checksec.rs provides a standalone binary in addition to the library used by the browser frontend. Files can be analyzed using this binary with the following command:
```
./checksec --file <filepath>
```


