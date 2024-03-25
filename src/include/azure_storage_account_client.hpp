#pragma once

#include "auth/azure_device_code_credential.hpp"
#include "azure_parsed_url.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/main/secret/secret.hpp"
#include <azure/storage/blobs/blob_service_client.hpp>
#include <azure/storage/files/datalake/datalake_service_client.hpp>
#include <string>

namespace duckdb {

std::shared_ptr<AzureDeviceCodeCredential> CreateDeviceCodeCredential(FileOpener *opener, const KeyValueSecret &secret);

Azure::Storage::Blobs::BlobServiceClient ConnectToBlobStorageAccount(FileOpener *opener, const std::string &path,
                                                                     const AzureParsedUrl &azure_parsed_url);

Azure::Storage::Files::DataLake::DataLakeServiceClient
ConnectToDfsStorageAccount(FileOpener *opener, const std::string &path, const AzureParsedUrl &azure_parsed_url);

} // namespace duckdb
