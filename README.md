

## Experimental warning
This extension is currently in an experimental state. Feel free to try it out, but be aware some things
may not work as expected.

# DuckDB Azure Extension
This extension adds a filesystem abstraction for Azure blob storage to DuckDB.

## Binary distribution
Binaries are available in the main extension repository for DuckDB only for nightly builds at the moment, but will be 
available next release of DuckDB (v0.9.0)

## Supported architectures
The extension is tested & distributed for Linux (x64), MacOS (x64, arm64) and Windows (x64)

## Documentation

See the [Azure page in the DuckDB documentation](https://duckdb.org/docs/extensions/azure).

Check out the tests in `test/sql` for more examples.

## Building
This extension depends on the Azure c++ sdk. To build it, either install that manually, or use vcpkg
to do dependency management. To install vcpkg check out the docs [here](https://vcpkg.io/en/getting-started.html).
Then to build this extension run:

```shell
VCPKG_TOOLCHAIN_PATH=<path_to_your_vcpkg_toolchain> make
```
