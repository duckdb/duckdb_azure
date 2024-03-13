#!/bin/bash

# This script is called manually for now. Use it to create and populate the azure test buckets against which the
# CI can then run tests

# Create container
az storage fs create --name testing-private --account-name $AZURE_STORAGE_ACCOUNT
az storage fs create --name testing-public  --account-name $AZURE_STORAGE_ACCOUNT --public-access filesystem

copy_file() {
  local from="${1}"
  local to="${2}"
  az storage fs file upload --source "${from}" --path "${to}" --file-system "testing-private" --account-name "${AZURE_STORAGE_ACCOUNT}" --overwrite
  az storage fs file upload --source "${from}" --path "${to}" --file-system "testing-public"  --account-name "${AZURE_STORAGE_ACCOUNT}" --overwrite
}

while read filepath; do
    remote_filepath="$(echo "${filepath}" | cut -c 7-)"
    copy_file "${filepath}" "${remote_filepath}"
done < <(find ./data -type f)
