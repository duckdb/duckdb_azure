#!/bin/bash

# This script is called manually for now. Use it to create and populate the azure test buckets against which the
# CI can then run tests

# Create container
az storage container create -n testing-private --account-name $AZURE_STORAGE_ACCOUNT
az storage container create -n testing-public  --account-name $AZURE_STORAGE_ACCOUNT --public-access container

copy_file() {
  local from="${1}"
  local to="${2}"
  az storage blob upload --file "${from}" --name "${to}" --container-name "testing-private" --account-name "${AZURE_STORAGE_ACCOUNT}" --overwrite
  az storage blob upload --file "${from}" --name "${to}" --container-name "testing-public"  --account-name "${AZURE_STORAGE_ACCOUNT}" --overwrite
}

while read filepath; do
    remote_filepath="$(echo "${filepath}" | cut -c 7-)"
    copy_file "${filepath}" "${remote_filepath}"
done < <(find ./data -type f)
