# athp
freebsd ath10k port

If you would like to build this for your machine follow the instructions below:
cd to your working directory, typically your home directory.
then run the following command.

git clone https://github.com/erikarn/athp.git

once you have run this command you will need to edit build_mobule in the following path:
athp/otus/freebsd/src/sys/modules/build_module


the code looks like the following:

```
#!/bin/sh

X_SRCDIR=${X_SRCDIR:="/home/adrian/work/freebsd/head/src/"}
X_KERNDIR=${X_KERNDIR:="/home/adrian/work/freebsd/head/obj/usr/home/adrian/work/freebsd/head/src/sys/GERTRUDE/"}
X_KMODOWN=${X_KMODOWN:="adrian"}
X_KMODGRP=${X_KMODGRP:="adrian"}

# This allows for -HEAD includes for net80211 ..
env CFLAGS="-I../../../sys/" \
make \
	MODULES_OVERRIDE="" \
	DEBUG_FLAGS="-g" \
	DEBUG_FLAGS="-g" \
	KMODDIR="/home/adrian/git/github/erikarn/athp/otus/freebsd/modules/" \
	KMODOWN="${X_KMODOWN}" \
	KMODGRP="${X_KMODGRP}" \
	MAKESYSPATH="${X_SRCDIR}/share/mk" \
	SYSDIR="${X_SRCDIR}/sys/" \
	KERNBUILDDIR="${X_KERNDIR}" \
	KERN_DEBUGDIR="" \
	$@
```
you will need to change X_SRCDIR to the path of the src of the freebsd kernel.
most likely if you follow the kernel build instructions your X_SRCDIR path will be
/usr/src/

This driver requires a minimum kernel version of 12.0

The next variable you must set is X_KERNDIR change the current path to the build path of the kernels build output.
If you have a typical normal built kernel where your source is in /usr/src/
most likely your X_KERNDIR will be /usr/obj/usr/src/amd64.amd64//sys/GENERIC/

the next parameter you need to change is KMODDIR, 
this will be the path to athp/otus/freebsd/modules This is the github clone path basically.
When you are done with this you are ready to run ./build_modules in the path
athp/otus/freebsd/src/sys/modules/

Instructions on how to build and compile freebsd 12:
https://www.freebsd.org/doc/handbook/makeworld.html#updating-src-obtaining-src
https://www.freebsd.org/doc/handbook/makeworld.html
