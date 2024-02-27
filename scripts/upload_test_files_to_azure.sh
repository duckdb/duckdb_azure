#!/bin/bash

# This script is called manually for now. Use it to create and populate the azure test buckets against which the
# CI can then run tests

# Create container
az storage container create -n testing-private --account-name $AZURE_STORAGE_ACCOUNT
az storage container create -n testing-public --account-name $AZURE_STORAGE_ACCOUNT --public-access container

# Upload test files
for filename in ./data/*; do
  az storage blob upload -f $filename -c testing-private --account-name $AZURE_STORAGE_ACCOUNT --overwrite
  az storage blob upload -f $filename -c testing-public --account-name $AZURE_STORAGE_ACCOUNT --overwrite
done