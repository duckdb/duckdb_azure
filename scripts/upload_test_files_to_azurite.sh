#!/bin/bash

# Default Azurite connection string (see: https://github.com/Azure/Azurite)
conn_string="DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;QueueEndpoint=http://127.0.0.1:10001/devstoreaccount1;TableEndpoint=http://127.0.0.1:10002/devstoreaccount1;"

# Create container
az storage container create -n testing-private  --connection-string $conn_string
az storage container create -n testing-public  --connection-string $conn_string --public-access blob

# Upload test files
for filename in ./data/*; do
  az storage blob upload -f $filename -c testing-private --connection-string $conn_string
  az storage blob upload -f $filename -c testing-public --connection-string $conn_string
done