# Test data

This directory contains test data that is uploaded to Azure tests servers in CI. What this means is that when adding
files in this directory, the `test/sql/test_data_integrity.test` should be updated, otherwise CI will fail (see [gen_check_file script](../scripts/gen_check_file.sh)).

## Partitioned

Partitionned data has been add to test the integration of DFS storage account.

Data has been generated from the `l.csv` source file with the following code:

```sh
spark-shell --master "local[1]"
```

```scala
val hadoopConf = spark.sparkContext.hadoopConfiguration
val fs = org.apache.hadoop.fs.FileSystem.get(hadoopConf)
fs.setWriteChecksum(false)

spark.conf.set("mapreduce.fileoutputcommitter.marksuccessfuljobs", "false")

spark.read
    .option("header", true)
    .csv("D:/gitws/duckdb_azure/data/l.csv")
    .withColumn("l_receipmonth", substring($"l_receiptdate", 0, 4))
    .withColumn("l_shipmode", regexp_replace($"l_shipmode", " ", "_"))
    .where($"l_receipmonth" >= 1997)
    .where($"l_shipmode".isin("AIR", "SHIP", "TRUCK"))
    .write
    .partitionBy("l_receipmonth", "l_shipmode")
    .option("header", true)
    .csv("D:/partitioned")
```

```sh
find ./partitioned -type f | xargs -I {} bash -c 'f="{}"; mv $f $(dirname $f)/data.csv'
```

Generate expected output

```scala
val df = (spark.read
    .option("header", true)
    .csv("D:/partitioned"))

df.count
// 6936

df.where($"l_shipmode" === "TRUCK").count
// 2317

df.where($"l_receipmonth" === "1997").where($"l_shipmode" === "TRUCK").count
// 1291
```
