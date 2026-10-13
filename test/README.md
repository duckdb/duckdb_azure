# Testing the quack extension
This directory contains all the tests for the quack extension. The `sql` directory holds tests that are written as [SQLLogicTests](https://duckdb.org/dev/sqllogictest/intro.html). DuckDB aims to have most its tests in this format as SQL statements, so for the quack extension, this should probably be the goal too. However, client specific testing is also available.

The root makefile contains targets to build and run all of these tests. To run the SQLLogicTests:
```bash
make test
```

To run the python tests:
```sql
make test_python
```

For other client tests check the makefile in the root of this repository.

## Connection-string tests

`azure_connection_string.test` covers input validation and account matching
without network access. `azure_connection_string_azurite.test` exercises shared
keys, account and container SAS tokens, anonymous endpoints, and development
storage with both secrets and the legacy connection-string setting.
The legacy setting applies only to Blob storage; Data Lake uses secrets.

The integration test requires two Azurite instances: the regular test instance
on Blob port 28000, and a second instance on the default Blob port 10000 for
`UseDevelopmentStorage=true`. Use separate `--location` directories for their
data. The fixture upload script creates the required containers on both
instances, and the `env_azurite` wrapper enables the integration test. Local CI
starts both instances on Windows, Linux, and macOS.

All embedded shared keys and SAS tokens are fixtures derived from Azurite's
public, well-known test key.