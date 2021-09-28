# What is DHCP-PKT ?

dhcp-pkt is a module for working on dhcp packets.

We can analyze dhcp packets or create new dhcp packets.

## Build

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Run tests

```bash
cd build/tests/main
./tests
```

Note: `tests` program need `fake_data` folder for reading data.

You should cd to `build/tests/main` directory or copy `tests` with `fake_data` on some folder.

Anyway `tests` and `fake_data` should be together.

## Usage

After building project we have a static library named `libpkt.a`.

You can use this module on every project.