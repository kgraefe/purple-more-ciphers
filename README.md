# Purple More Ciphers

This plugin provides additional ciphers for libpurple clients such as Pidgin
that can be used by other plugins.

## Installation on Linux
To install the plugin on Linux you need to extract a release tarball and
compile it from source:

    sudo apt install bats pidgin-dev libnss3-dev libargon2-0-dev
    ./configure
    make
    make check
    sudo make install

**Note:** By default the plugin will be installed to `/usr/local`.  If you
installed Pidgin through your package manager, it is most likely installed into
`/usr` (i.e. `which pidgin` returns `/usr/bin/pidgin`). Use
`./configure --prefix=/usr` in this case.

**Note:** When you use the repository directly or one of those auto-generated
"Source code" archives, you need to run `./autogen.sh` before running
`./configure`.

## Building on Windows
In order to build the plugin for Windows an already-compiled source tree of
Pidgin is required. Please see the [Pidgin for Windows Build
Instructions][1] for details.

Additionally you need to download
[mingw-w64-i686-argon2-20171227-4-any.pkg.tar.xz][2] from [repo.msys2.org][3]
and extract it into `argon2-20171227` in the `win32-dev` directory (the
subdirectory must be created).

After that you need to create a file named `local.mak` that points to the Pidgin
source tree, e.g.:

    PIDGIN_TREE_TOP=$(PLUGIN_TOP)/../../pidgin-2.10.11

Now you can build the plugin:

    make -f Makefile.mingw

[1]: https://developer.pidgin.im/wiki/BuildingWinPidgin
[2]: http://repo.msys2.org/mingw/i686/mingw-w64-i686-argon2-20171227-4-any.pkg.tar.xz
[3]: http://repo.msys2.org/mingw/i686/
