# DuckDB Azure Extension

This extension adds a filesystem abstraction for Azure blob storage to DuckDB. To use it, install latest DuckDB. The extension currently supports only **reads** and **globs**.

> BUGBUG: recommend cred chain, mention alternatives connection_string + access_token + service_principal

The easiest way to get started is by using a connection string to create a DuckDB secret:
```sql
CREATE SECRET (
    TYPE AZURE,
    CONNECTION_STRING '<value>'
);
```
Alternatively, you can let the azure extension automatically fetch your azure credentials, check out the [docs](https://duckdb.org/docs/extensions/azure#credential_chain-provider) on how to do that.

Then to query a file on azure:
```sql
SELECT count(*) FROM 'azure://<my_container>/<my_file>.<parquet_or_csv>';
```

Globbing is also supported:
```sql
SELECT count(*) FROM 'azure://dummy_container/*.csv';
```

## Supported architectures

The extension is tested & distributed for Linux (x64, arm64), MacOS (x64, arm64) and Windows (x64)

## Documentation

See the [Azure page in the DuckDB documentation](https://duckdb.org/docs/extensions/azure).

Check out the tests in `test/sql` for more examples.

## Building

For development, this extension requires [CMake](https://cmake.org), Python3, a `C++11` compliant compiler, and the Azure C++ SDK. Run `make` in the root directory to compile the sources. Run `make debug` to build a non-optimized debug version. Run `make test` to verify that your version works properly after making changes. Install the Azure C++ SDK using [vcpkg](https://vcpkg.io/en/getting-started.html) and set the `VCPKG_TOOLCHAIN_PATH` environment variable when building.

```shell
sudo apt-get update && sudo apt-get install -y git g++ cmake ninja-build libssl-dev
git clone --recursive https://github.com/duckdb/duckdb_azure
git clone https://github.com/microsoft/vcpkg
./vcpkg/bootstrap-vcpkg.sh
cd duckdb_azure
GEN=ninja VCPKG_TOOLCHAIN_PATH=$PWD/../vcpkg/scripts/buildsystems/vcpkg.cmake make
```

Please also refer to our [Build Guide](https://duckdb.org/dev/building) and [Contribution Guide]([CONTRIBUTING.md](https://github.com/duckdb/duckdb/blob/main/CONTRIBUTING.md)).
