#pragma once

#include "azure_parsed_url.hpp"
#include "duckdb/common/file_opener.hpp"
#include <azure/storage/blobs/blob_service_client.hpp>
#include <string>

namespace duckdb {

Azure::Storage::Blobs::BlobServiceClient ConnectToStorageAccount(FileOpener *opener, const std::string &path,
                                                                 const AzureParsedUrl &azure_parsed_url);

} // namespace duckdb
