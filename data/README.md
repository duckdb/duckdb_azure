# Test data

This directory contains test data that is uploaded to Azure tests servers in CI. What this means is that when adding
files in this directory, the `test/sql/test_data_integrity.test` should be updated, otherwise CI will fail (see [gen_check_file script](../scripts/gen_check_file.sh)).

## Partitioned

Partitionned data has been add to test the integration of DFS storage account.

Data has been generated from the `l.csv` source file with the following code:

```sql
COPY (
    SELECT *, date_part('year', l_receiptdate) as l_receipmonth
    FROM './data/l.csv'
    WHERE l_receipmonth >= 1997
    AND   l_shipmode IN ('AIR', 'SHIP', 'TRUCK')
)
TO './data/partitioned' (FORMAT CSV, PARTITION_BY (l_receipmonth, l_shipmode), OVERWRITE_OR_IGNORE 1);
```
