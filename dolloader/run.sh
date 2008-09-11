#!/bin/bash
make clean && make && powerpc-gekko-objcopy -O binary dolloader.elf dolloader.bin && cp dolloader.bin ../patchingwadinstaller/data
