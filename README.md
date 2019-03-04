Idecomp
=======

This program lets you extract files form InstallShield 3 archives.  
These ones are usually produced and extracted with Icomp.exe from ICOMP95.zip that can be found on various places across Internet.

It handles archives with .Z suffix and multi-part archives with .1, .2, ... suffixes as well.

InstallShield archives data is compressed with the (now obsolete) PKWare Data Compression Library.  
This program include work from Sven Kochmann (https://github.com/Schallaven/pwexplode) with a bit of optimisation.

This software follows PWExplode license and is released under the GNU GPL v3 license.

## How to recognize an InstallShield 3 archive

It has a .Z or .1, .2, ... suffix.

Each file has a header which looks like `13 5D 65 8C 01 02 00` in an hexadecimal editor.

## Usage

To list files:

`idecomp.py -l achive.Z`

To extract:

`idecomp.py archive.Z`

Idecomp supports an optional glob to only extract specific files:

`idecomp.py archive.Z *.txt`

You can change the encoding of file names stored in archives with the `-e` switch but the default (Windows-1252) should be fine for US and Western Europe.

By default, when processing multi-part archives, Idecomp only extracts files in the considered part of the archive like the original Icomp.exe.  
To extract everything, use the `-a` switch.
