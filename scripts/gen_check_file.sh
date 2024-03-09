#!/bin/bash

# This script allow to generate the content of the test_data_integrity.test test

cd "$(dirname "${0}")/.."

cat <<'EOF'
# name: test/sql/test_data_integrity.test
# description: Check the test data looks as expected
# group: [azure]

require azure

require parquet

require-env DUCKDB_AZURE_PERSISTENT_SECRET_AVAILABLE

# Note:
# * if this test fails, you probably added a file to `./data` when doing so, they need to be added here too
# * we add contains(file, '.') to avoid failure when using dfs storage (as DFS handle the idea of directory they are also part of the result)

### Check file listing
EOF

echo "query I"
echo "SELECT file FROM glob(\"azure://testing-public/**\") WHERE contains(file, '.') ORDER BY file;"
echo "----"
find ./data -type f | sort | cut -c 8- | xargs -I{} echo "azure://testing-public/{}"

echo

echo "query I"
echo "SELECT file FROM glob(\"azure://testing-private/**\") WHERE contains(file, '.') ORDER BY file;"
echo "----"
find ./data -type f | sort | cut -c 8- | xargs -I{} echo "azure://testing-private/{}"

echo

echo "### Check each file individually"
i=1
while read filepath; do
    remote_filepath="$(echo "${filepath}" | cut -c 8-)"
    echo "# ${remote_filepath}"
    echo "query I nosort file${i}"
    echo "FROM '${filepath}';"
    echo
    echo "query I nosort file${i}"
    echo "FROM 'azure://testing-public/${remote_filepath}';"
    echo
    echo "query I nosort file${i}"
    echo "FROM 'azure://testing-private/${remote_filepath}';"
    echo
    i=$((i+1))
done < <(find ./data -type f | sort | grep -v README.md)


