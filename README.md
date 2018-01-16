# kBench9000 &ndash; simple kernel land cycle counter
### by [Jason A. Donenfeld](mailto:jason@zx2c4.com)

This is a very simple kernel land cycle counter. To use, simply edit `function.h`,
add any other `.c` files and mention them in the `kbench9000-y +=` line of the
`Makefile`, and then type:

```
$ make run
```

![Expected kBench9000 output](https://data.zx2c4.com/kbench9000-screenshot.png)

### Kernel Toolchain

You'll need to have a working kernel toolchain, usually achievable by:

```
$ sudo apt install linux-headers-$(uname -r) build-essential
```

or

```
$ sudo dnf install kernel-devel @development-tools
```
