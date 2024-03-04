# Test data
This directory contains test data that is uploaded to Azure tests servers in CI. What this means is that when adding
files in this directory, the `test/sql/test_data_integrity.test` should be updated, otherwise CI will fail.