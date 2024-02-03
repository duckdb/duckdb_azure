#pragma once

#include "duckdb/common/file_opener.hpp"
#include <azure/storage/blobs/blob_service_client.hpp>
#include <string>

namespace duckdb {

Azure::Storage::Blobs::BlobServiceClient ConnectToStorageAccount(FileOpener *opener, const std::string &path,
                                                                 const std::string &storage_account_name,
                                                                 const std::string &provided_endpoint);

} // namespace duckdb
