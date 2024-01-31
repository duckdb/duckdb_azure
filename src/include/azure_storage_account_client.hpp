#pragma once

#include "duckdb/common/file_opener.hpp"
#include <azure/storage/blobs/blob_service_client.hpp>
#include <string>

namespace duckdb {

Azure::Storage::Blobs::BlobServiceClient ConnectToStorageAccount(FileOpener *opener, const std::string &path);

} // namespace duckdb
