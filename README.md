# DuckDB Azure Extension
This extension adds a filesystem abstraction for Azure blob storage to DuckDB. To use it, install latest DuckDB. The extension currently supports only **reads** and **globs**.

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
This extension depends on the Azure c++ sdk. To build it, either install that manually, or use vcpkg
to do dependency management. To install vcpkg check out the docs [here](https://vcpkg.io/en/getting-started.html).
Then to build this extension run:

```shell
VCPKG_TOOLCHAIN_PATH=<path_to_your_vcpkg_toolchain> make
```
