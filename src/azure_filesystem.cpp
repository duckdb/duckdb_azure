#include "azure_filesystem.hpp"

#include "azure_storage_account_client.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/http_state.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/scalar/string_functions.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/client_data.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include <azure/storage/blobs.hpp>
#include <azure/core/diagnostics/logger.hpp>
#include <cstdlib>
#include <memory>
#include <utility>

namespace duckdb {

using namespace Azure::Core::Diagnostics;

// Constant
const std::string AzureStorageFileSystem::DEFAULT_AZURE_STORAGE_ACCOUNT = "default_azure_storage_account";

// globals for collection Azure SDK logging information
mutex AzureStorageFileSystem::azure_log_lock = {};
weak_ptr<HTTPState> AzureStorageFileSystem::http_state = std::weak_ptr<HTTPState>();
bool AzureStorageFileSystem::listener_set = false;

// TODO: extract received/sent bytes information
static void Log(Logger::Level level, std::string const &message) {
	auto http_state_ptr = AzureStorageFileSystem::http_state;
	auto http_state = http_state_ptr.lock();
	if (!http_state && AzureStorageFileSystem::listener_set) {
		throw std::runtime_error("HTTP state weak pointer failed to lock");
	}
	if (message.find("Request") != std::string::npos) {
		if (message.find("Request : HEAD") != std::string::npos) {
			http_state->head_count++;
		} else if (message.find("Request : GET") != std::string::npos) {
			http_state->get_count++;
		} else if (message.find("Request : POST") != std::string::npos) {
			http_state->post_count++;
		} else if (message.find("Request : PUT") != std::string::npos) {
			http_state->put_count++;
		}
	}
}

static AzureReadOptions ParseAzureReadOptions(FileOpener *opener) {
	AzureReadOptions options;

	Value concurrency_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_read_transfer_concurrency", concurrency_val)) {
		options.transfer_concurrency = concurrency_val.GetValue<int32_t>();
	}

	Value chunk_size_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_read_transfer_chunk_size", chunk_size_val)) {
		options.transfer_chunk_size = chunk_size_val.GetValue<int64_t>();
	}

	Value buffer_size_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_read_buffer_size", buffer_size_val)) {
		options.buffer_size = buffer_size_val.GetValue<idx_t>();
	}

	return options;
}

// taken from s3fs.cpp TODO: deduplicate!
static bool Match(vector<string>::const_iterator key, vector<string>::const_iterator key_end,
                  vector<string>::const_iterator pattern, vector<string>::const_iterator pattern_end) {

	while (key != key_end && pattern != pattern_end) {
		if (*pattern == "**") {
			if (std::next(pattern) == pattern_end) {
				return true;
			}
			while (key != key_end) {
				if (Match(key, key_end, std::next(pattern), pattern_end)) {
					return true;
				}
				key++;
			}
			return false;
		}
		if (!LikeFun::Glob(key->data(), key->length(), pattern->data(), pattern->length())) {
			return false;
		}
		key++;
		pattern++;
	}
	return key == key_end && pattern == pattern_end;
}

//////// AzureContextState ////////
AzureContextState::AzureContextState(Azure::Storage::Blobs::BlobServiceClient client)
    : service_client(client), is_valid(true) {
}

Azure::Storage::Blobs::BlobContainerClient
AzureContextState::GetBlobContainerClient(const std::string &blobContainerName) const {
	return service_client.GetBlobContainerClient(blobContainerName);
}

bool AzureContextState::IsValid() const {
	return is_valid;
}

void AzureContextState::QueryEnd() {
	is_valid = false;
}

//////// AzureStorageFileHandle ////////
AzureStorageFileHandle::AzureStorageFileHandle(FileSystem &fs, string path_p, uint8_t flags,
                                               Azure::Storage::Blobs::BlobClient blob_client,
                                               const AzureReadOptions &read_options)
    : FileHandle(fs, std::move(path_p)), flags(flags), length(0), last_modified(time_t()), buffer_available(0),
      buffer_idx(0), file_offset(0), buffer_start(0), buffer_end(0), blob_client(blob_client),
      read_options(read_options) {
	try {
		auto res = blob_client.GetProperties();
		length = res.Value.BlobSize;
	} catch (Azure::Storage::StorageException &e) {
		throw IOException("AzureStorageFileSystem open file '" + path + "' failed with code'" + e.ErrorCode +
		                  "',Reason Phrase: '" + e.ReasonPhrase + "', Message: '" + e.Message + "'");
	} catch (std::exception &e) {
		throw IOException("AzureStorageFileSystem could not open file: '%s', unknown error occurred, this could mean "
		                  "the credentials used were wrong. Original error message: '%s' ",
		                  path, e.what());
	}

	if (flags & FileFlags::FILE_FLAGS_READ) {
		read_buffer = duckdb::unique_ptr<data_t[]>(new data_t[read_options.buffer_size]);
	}
}

//////// AzureStorageFileSystem ////////
AzureStorageFileSystem::~AzureStorageFileSystem() {
	Logger::SetListener(nullptr);
	AzureStorageFileSystem::listener_set = false;
}

unique_ptr<AzureStorageFileHandle> AzureStorageFileSystem::CreateHandle(const string &path, uint8_t flags,
                                                                        FileLockType lock,
                                                                        FileCompressionType compression,
                                                                        FileOpener *opener) {
	if (opener == nullptr) {
		throw InternalException("Cannot do Azure storage CreateHandle without FileOpener");
	}

	D_ASSERT(compression == FileCompressionType::UNCOMPRESSED);

	auto parsed_url = ParseUrl(path);
	auto storage_account = GetOrCreateStorageAccountContext(opener, path);
	auto container = storage_account->GetBlobContainerClient(parsed_url.container);
	auto blob_client = container.GetBlockBlobClient(parsed_url.path);

	auto read_options = ParseAzureReadOptions(opener);
	return make_uniq<AzureStorageFileHandle>(*this, path, flags, blob_client, read_options);
}

unique_ptr<FileHandle> AzureStorageFileSystem::OpenFile(const string &path, uint8_t flags, FileLockType lock,
                                                        FileCompressionType compression, FileOpener *opener) {
	D_ASSERT(compression == FileCompressionType::UNCOMPRESSED);

	Value value;
	bool enable_http_stats = false;
	auto context = FileOpener::TryGetClientContext(opener);
	if (FileOpener::TryGetCurrentSetting(opener, "azure_http_stats", value)) {
		enable_http_stats = value.GetValue<bool>();
	}

	if (context && enable_http_stats) {
		unique_lock<mutex> lck(AzureStorageFileSystem::azure_log_lock);
		AzureStorageFileSystem::http_state = HTTPState::TryGetState(opener);

		if (!AzureStorageFileSystem::listener_set) {
			Logger::SetListener(std::bind(&Log, std::placeholders::_1, std::placeholders::_2));
			Logger::SetLevel(Logger::Level::Verbose);
			AzureStorageFileSystem::listener_set = true;
		}
	}

	if (flags & FileFlags::FILE_FLAGS_WRITE) {
		throw NotImplementedException("Writing to Azure containers is currently not supported");
	}

	auto handle = CreateHandle(path, flags, lock, compression, opener);
	return std::move(handle);
}

int64_t AzureStorageFileSystem::GetFileSize(FileHandle &handle) {
	auto &afh = handle.Cast<AzureStorageFileHandle>();
	return afh.length;
}

time_t AzureStorageFileSystem::GetLastModifiedTime(FileHandle &handle) {
	auto &afh = handle.Cast<AzureStorageFileHandle>();
	return afh.last_modified;
}

bool AzureStorageFileSystem::CanHandleFile(const string &fpath) {
	return fpath.rfind("azure://", 0) * fpath.rfind("az://", 0) == 0;
}

void AzureStorageFileSystem::Seek(FileHandle &handle, idx_t location) {
	auto &sfh = handle.Cast<AzureStorageFileHandle>();
	sfh.file_offset = location;
}

void AzureStorageFileSystem::FileSync(FileHandle &handle) {
	throw NotImplementedException("FileSync for Azure Storage files not implemented");
}

int64_t AzureStorageFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &hfh = handle.Cast<AzureStorageFileHandle>();
	idx_t max_read = hfh.length - hfh.file_offset;
	nr_bytes = MinValue<idx_t>(max_read, nr_bytes);
	Read(handle, buffer, nr_bytes, hfh.file_offset);
	return nr_bytes;
}

vector<string> AzureStorageFileSystem::Glob(const string &path, FileOpener *opener) {
	if (opener == nullptr) {
		throw InternalException("Cannot do Azure storage Glob without FileOpener");
	}

	auto azure_url = AzureStorageFileSystem::ParseUrl(path);
	auto storage_account = GetOrCreateStorageAccountContext(opener, path);

	// Azure matches on prefix, not glob pattern, so we take a substring until the first wildcard
	auto first_wildcard_pos = azure_url.path.find_first_of("*[\\");
	if (first_wildcard_pos == string::npos) {
		return {path};
	}

	string shared_path = azure_url.path.substr(0, first_wildcard_pos);
	auto container_client = storage_account->GetBlobContainerClient(azure_url.container);

	// vector<Azure::Storage::Blobs::Models::BlobItem> found_keys;
	const auto pattern_splits = StringUtil::Split(azure_url.path, "/");
	vector<string> result;

	Azure::Storage::Blobs::ListBlobsOptions options;
	options.Prefix = shared_path;
	while (true) {
		// Perform query
		Azure::Storage::Blobs::ListBlobsPagedResponse res;
		try {
			res = container_client.ListBlobs(options);
		} catch (Azure::Storage::StorageException &e) {
			throw IOException("AzureStorageFileSystem Read to " + path + " failed with " + e.ErrorCode +
			                  "Reason Phrase: " + e.ReasonPhrase);
		}

		// Assuming that in the majority of the case it's wildcard
		result.reserve(result.size() + res.Blobs.size());

		// Ensure that the retrieved element match the expected pattern
		for (const auto &key : res.Blobs) {
			vector<string> key_splits = StringUtil::Split(key.Name, "/");
			bool is_match = Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end());

			if (is_match) {
				auto result_full_url = azure_url.prefix + azure_url.container + "/" + key.Name;
				result.push_back(result_full_url);
			}
		}

		// Manage Azure pagination
		if (res.NextPageToken) {
			options.ContinuationToken = res.NextPageToken;
		} else {
			break;
		}
	}

	return result;
}

// TODO: this code is identical to HTTPFS, look into unifying it
void AzureStorageFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &hfh = handle.Cast<AzureStorageFileHandle>();

	idx_t to_read = nr_bytes;
	idx_t buffer_offset = 0;

	// Don't buffer when DirectIO is set.
	if (hfh.flags & FileFlags::FILE_FLAGS_DIRECT_IO && to_read > 0) {
		ReadRange(hfh, location, (char *)buffer, to_read);
		hfh.buffer_available = 0;
		hfh.buffer_idx = 0;
		hfh.file_offset = location + nr_bytes;
		return;
	}

	if (location >= hfh.buffer_start && location < hfh.buffer_end) {
		hfh.file_offset = location;
		hfh.buffer_idx = location - hfh.buffer_start;
		hfh.buffer_available = (hfh.buffer_end - hfh.buffer_start) - hfh.buffer_idx;
	} else {
		// reset buffer
		hfh.buffer_available = 0;
		hfh.buffer_idx = 0;
		hfh.file_offset = location;
	}
	while (to_read > 0) {
		auto buffer_read_len = MinValue<idx_t>(hfh.buffer_available, to_read);
		if (buffer_read_len > 0) {
			D_ASSERT(hfh.buffer_start + hfh.buffer_idx + buffer_read_len <= hfh.buffer_end);
			memcpy((char *)buffer + buffer_offset, hfh.read_buffer.get() + hfh.buffer_idx, buffer_read_len);

			buffer_offset += buffer_read_len;
			to_read -= buffer_read_len;

			hfh.buffer_idx += buffer_read_len;
			hfh.buffer_available -= buffer_read_len;
			hfh.file_offset += buffer_read_len;
		}

		if (to_read > 0 && hfh.buffer_available == 0) {
			auto new_buffer_available = MinValue<idx_t>(hfh.read_options.buffer_size, hfh.length - hfh.file_offset);

			// Bypass buffer if we read more than buffer size
			if (to_read > new_buffer_available) {
				ReadRange(hfh, location + buffer_offset, (char *)buffer + buffer_offset, to_read);
				hfh.buffer_available = 0;
				hfh.buffer_idx = 0;
				hfh.file_offset += to_read;
				break;
			} else {
				ReadRange(hfh, hfh.file_offset, (char *)hfh.read_buffer.get(), new_buffer_available);
				hfh.buffer_available = new_buffer_available;
				hfh.buffer_idx = 0;
				hfh.buffer_start = hfh.file_offset;
				hfh.buffer_end = hfh.buffer_start + new_buffer_available;
			}
		}
	}
}

bool AzureStorageFileSystem::FileExists(const string &filename) {
	try {
		auto handle = OpenFile(filename, FileFlags::FILE_FLAGS_READ);
		auto &sfh = handle->Cast<AzureStorageFileHandle>();
		if (sfh.length == 0) {
			return false;
		}
		return true;
	} catch (...) {
		return false;
	};
}

void AzureStorageFileSystem::ReadRange(FileHandle &handle, idx_t file_offset, char *buffer_out, idx_t buffer_out_len) {
	auto &afh = handle.Cast<AzureStorageFileHandle>();

	try {
		// Specify the range
		Azure::Core::Http::HttpRange range;
		range.Offset = (int64_t)file_offset;
		range.Length = buffer_out_len;
		Azure::Storage::Blobs::DownloadBlobToOptions options;
		options.Range = range;
		options.TransferOptions.Concurrency = afh.read_options.transfer_concurrency;
		options.TransferOptions.InitialChunkSize = afh.read_options.transfer_chunk_size;
		options.TransferOptions.ChunkSize = afh.read_options.transfer_chunk_size;
		auto res = afh.blob_client.DownloadTo((uint8_t *)buffer_out, buffer_out_len, options);

	} catch (Azure::Storage::StorageException &e) {
		throw IOException("AzureStorageFileSystem Read to " + afh.path + " failed with " + e.ErrorCode +
		                  "Reason Phrase: " + e.ReasonPhrase);
	}
}

AzureParsedUrl AzureStorageFileSystem::ParseUrl(const string &url) {
	string container, prefix, path;

	if (url.rfind("azure://", 0) * url.rfind("az://", 0) != 0) {
		throw IOException("URL needs to start with azure:// or az://");
	}
	auto prefix_end_pos = url.find("//") + 2;
	auto slash_pos = url.find('/', prefix_end_pos);
	if (slash_pos == string::npos) {
		throw IOException("URL needs to contain a '/' after the host");
	}
	container = url.substr(prefix_end_pos, slash_pos - prefix_end_pos);
	if (container.empty()) {
		throw IOException("URL needs to contain a bucket name");
	}

	prefix = url.substr(0, prefix_end_pos);
	path = url.substr(slash_pos + 1);
	return {container, prefix, path};
}

std::shared_ptr<AzureContextState> AzureStorageFileSystem::GetOrCreateStorageAccountContext(FileOpener *opener,
                                                                                            const std::string &path) {
	Value value;
	bool azure_context_caching = true;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_context_caching", value)) {
		azure_context_caching = value.GetValue<bool>();
	}

	std::shared_ptr<AzureContextState> result;
	if (azure_context_caching) {
		auto *client_context = FileOpener::TryGetClientContext(opener);

		auto &registered_state = client_context->registered_state;
		auto storage_account_it = registered_state.find(DEFAULT_AZURE_STORAGE_ACCOUNT);
		if (storage_account_it == registered_state.end()) {
			result = std::make_shared<AzureContextState>(ConnectToStorageAccount(opener, path));
			registered_state.insert(std::make_pair(DEFAULT_AZURE_STORAGE_ACCOUNT, result));
		} else {
			auto *azure_context_state = static_cast<AzureContextState *>(storage_account_it->second.get());
			// We keep the context valid until the QueryEnd (cf: AzureContextState#QueryEnd())
			// we do so because between queries the user can change the secret/variable that has been set
			// the side effect of that is that we will reconnect (potentially retrieve a new token) on each request
			if (!azure_context_state->IsValid()) {
				result = std::make_shared<AzureContextState>(ConnectToStorageAccount(opener, path));
				registered_state[DEFAULT_AZURE_STORAGE_ACCOUNT] = result;
			} else {
				result = std::shared_ptr<AzureContextState>(storage_account_it->second, azure_context_state);
			}
		}
	} else {
		result = std::make_shared<AzureContextState>(ConnectToStorageAccount(opener, path));
	}

	return result;
}

} // namespace duckdb
