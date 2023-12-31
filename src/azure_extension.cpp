#define DUCKDB_EXTENSION_MAIN

#include "azure_extension.hpp"

#include "azure_secret.hpp"
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
#include <azure/storage/blobs.hpp>
#include <azure/core/diagnostics/logger.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/azure_cli_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/storage/blobs.hpp>
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <iostream>

namespace duckdb {

using namespace Azure::Core::Diagnostics;

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

static Azure::Identity::ChainedTokenCredential::Sources
CreateCredentialChainFromSetting(const string &credential_chain) {
	auto chain_list = StringUtil::Split(credential_chain, ';');
	Azure::Identity::ChainedTokenCredential::Sources result;

	for (const auto &item : chain_list) {
		if (item == "cli") {
			result.push_back(std::make_shared<Azure::Identity::AzureCliCredential>());
		} else if (item == "managed_identity") {
			result.push_back(std::make_shared<Azure::Identity::ManagedIdentityCredential>());
		} else if (item == "env") {
			result.push_back(std::make_shared<Azure::Identity::EnvironmentCredential>());
		} else if (item == "default") {
			result.push_back(std::make_shared<Azure::Identity::DefaultAzureCredential>());
		} else if (item != "none") {
			throw InvalidInputException("Unknown credential provider found: " + item);
		}
	}

	return result;
}

static AzureAuthentication ParseAzureAuthSettings(FileOpener *opener, const string &path) {
	AzureAuthentication auth;

	// Lookup Secret
	auto context = opener->TryGetClientContext();
	if (context) {
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*context);
		auto secret_lookup = context->db->config.secret_manager->LookupSecret(transaction, path, "azure");
		if (secret_lookup.HasMatch()) {
			const auto &secret = secret_lookup.GetSecret();
			auth.secret = &dynamic_cast<const KeyValueSecret &>(secret);
		}
	}

	Value connection_string_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_storage_connection_string", connection_string_val)) {
		auth.connection_string = connection_string_val.ToString();
	}

	Value account_name_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_account_name", account_name_val)) {
		auth.account_name = account_name_val.ToString();
	}

	Value endpoint_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_endpoint", endpoint_val)) {
		auth.endpoint = endpoint_val.ToString();
	}

	if (!auth.account_name.empty()) {
		string credential_chain;
		Value credential_chain_val;
		if (FileOpener::TryGetCurrentSetting(opener, "azure_credential_chain", credential_chain_val)) {
			auth.credential_chain = credential_chain_val.ToString();
		}
	}

	return auth;
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

static Azure::Storage::Blobs::BlobContainerClient GetContainerClient(AzureAuthentication &auth, AzureParsedUrl &url) {
	string connection_string;
	bool use_secret = false;
	string chain;
	string account_name;
	string endpoint;

	// Firstly, try to use the auth from the secret
	if (auth.secret) {
		// If connection string, we're done heres
		auto connection_string_value = auth.secret->TryGetValue("connection_string");
		if (!connection_string_value.IsNull()) {
			return Azure::Storage::Blobs::BlobContainerClient::CreateFromConnectionString(
			    connection_string_value.ToString(), url.container);
		}

		// Account_name can be used both for unauthenticated
		if (!auth.secret->TryGetValue("account_name").IsNull()) {
			use_secret = true;
			account_name = auth.secret->TryGetValue("account_name").ToString();
		}

		if (auth.secret->GetProvider() == "credential_chain") {
			use_secret = true;
			if (!auth.secret->TryGetValue("chain").IsNull()) {
				chain = auth.secret->TryGetValue("chain").ToString();
			}
			if (chain.empty()) {
				chain = "default";
			}
			if (!auth.secret->TryGetValue("endpoint").IsNull()) {
				endpoint = auth.secret->TryGetValue("endpoint").ToString();
			}
		}
	}

	if (!use_secret) {
		chain = auth.credential_chain;
		account_name = auth.account_name;
		endpoint = auth.endpoint;

		if (!auth.connection_string.empty()) {
			return Azure::Storage::Blobs::BlobContainerClient::CreateFromConnectionString(auth.connection_string,
			                                                                              url.container);
		}
	}

	if (endpoint.empty()) {
		endpoint = "blob.core.windows.net";
	}

	// Build credential chain, from last to first
	Azure::Identity::ChainedTokenCredential::Sources credential_chain;
	if (!chain.empty()) {
		credential_chain = CreateCredentialChainFromSetting(chain);
	}

	auto accountURL = "https://" + account_name + "." + endpoint;
	if (!credential_chain.empty()) {
		// A set of credentials providers was passed
		auto chainedTokenCredential = std::make_shared<Azure::Identity::ChainedTokenCredential>(credential_chain);
		Azure::Storage::Blobs::BlobServiceClient blob_service_client(accountURL, chainedTokenCredential);
		return blob_service_client.GetBlobContainerClient(url.container);
	} else if (!account_name.empty()) {
		return Azure::Storage::Blobs::BlobContainerClient(accountURL + "/" + url.container);
	} else {
		throw InvalidInputException("No valid Azure credentials found!");
	}
}

BlobClientWrapper::BlobClientWrapper(AzureAuthentication &auth, AzureParsedUrl &url) {
	auto container_client = GetContainerClient(auth, url);
	blob_client = make_uniq<Azure::Storage::Blobs::BlockBlobClient>(container_client.GetBlockBlobClient(url.path));
}

BlobClientWrapper::~BlobClientWrapper() = default;
Azure::Storage::Blobs::BlobClient *BlobClientWrapper::GetClient() {
	return blob_client.get();
}

AzureStorageFileSystem::~AzureStorageFileSystem() {
	Logger::SetListener(nullptr);
	AzureStorageFileSystem::listener_set = false;
}

AzureStorageFileHandle::AzureStorageFileHandle(FileSystem &fs, string path_p, uint8_t flags, AzureAuthentication &auth,
                                               const AzureReadOptions &read_options, AzureParsedUrl parsed_url)
    : FileHandle(fs, std::move(path_p)), flags(flags), length(0), last_modified(time_t()), buffer_available(0),
      buffer_idx(0), file_offset(0), buffer_start(0), buffer_end(0), blob_client(auth, parsed_url),
      read_options(read_options) {
	try {
		auto client = *blob_client.GetClient();
		auto res = client.GetProperties();
		length = res.Value.BlobSize;
	} catch (Azure::Storage::StorageException &e) {
		throw IOException("AzureStorageFileSystem open file '" + path + "' failed with code'" + e.ErrorCode +
		                  "',Reason Phrase: '" + e.ReasonPhrase + "', Message: '" + e.Message + "'");
	} catch (std::exception &e) {
		throw IOException("AzureStorageFileSystem could not open file: '%s', unknown error occured, this could mean "
		                  "the credentials used were wrong. Original error message: '%s' ",
		                  path, e.what());
	}

	if (flags & FileFlags::FILE_FLAGS_READ) {
		read_buffer = duckdb::unique_ptr<data_t[]>(new data_t[read_options.buffer_size]);
	}
}

unique_ptr<AzureStorageFileHandle> AzureStorageFileSystem::CreateHandle(const string &path, uint8_t flags,
                                                                        FileLockType lock,
                                                                        FileCompressionType compression,
                                                                        FileOpener *opener) {
	D_ASSERT(compression == FileCompressionType::UNCOMPRESSED);

	auto parsed_url = ParseUrl(path);
	auto azure_auth = ParseAzureAuthSettings(opener, path);
	auto read_options = ParseAzureReadOptions(opener);

	return make_uniq<AzureStorageFileHandle>(*this, path, flags, azure_auth, read_options, parsed_url);
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
		if (!context->client_data->http_state) {
			context->client_data->http_state = make_shared<HTTPState>();
		}
		AzureStorageFileSystem::http_state = context->client_data->http_state;

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
	auto &afh = (AzureStorageFileHandle &)handle;
	return afh.length;
}

time_t AzureStorageFileSystem::GetLastModifiedTime(FileHandle &handle) {
	auto &afh = (AzureStorageFileHandle &)handle;
	return afh.last_modified;
}

bool AzureStorageFileSystem::CanHandleFile(const string &fpath) {
	return fpath.rfind("azure://", 0) * fpath.rfind("az://", 0) == 0;
}

void AzureStorageFileSystem::Seek(FileHandle &handle, idx_t location) {
	auto &sfh = (AzureStorageFileHandle &)handle;
	sfh.file_offset = location;
}

void AzureStorageFileSystem::FileSync(FileHandle &handle) {
	throw NotImplementedException("FileSync for Azure Storage files not implemented");
}

static void LoadInternal(DatabaseInstance &instance) {
	// Load filesystem
	auto &fs = instance.GetFileSystem();
	fs.RegisterSubSystem(make_uniq<AzureStorageFileSystem>());

	// Load Secret functions
	CreateAzureSecretFunctions::Register(instance);

	// Load extension config
	auto &config = DBConfig::GetConfig(instance);
	config.AddExtensionOption("azure_storage_connection_string",
	                          "Azure connection string, used for authenticating and configuring azure requests",
	                          LogicalType::VARCHAR);
	config.AddExtensionOption(
	    "azure_account_name",
	    "Azure account name, when set, the extension will attempt to automatically detect credentials",
	    LogicalType::VARCHAR);
	config.AddExtensionOption("azure_credential_chain",
	                          "Ordered list of Azure credential providers, in string format separated by ';'. E.g. "
	                          "'cli;managed_identity;env'",
	                          LogicalType::VARCHAR, "none");
	config.AddExtensionOption("azure_endpoint",
	                          "Override the azure endpoint for when the Azure credential providers are used.",
	                          LogicalType::VARCHAR, "blob.core.windows.net");
	config.AddExtensionOption("azure_http_stats",
	                          "Include http info from the Azure Storage in the explain analyze statement. "
	                          "Notice that the result may be incorrect for more than one active DuckDB connection "
	                          "and the calculation of total received and sent bytes is not yet implemented.",
	                          LogicalType::BOOLEAN, false);

	AzureReadOptions default_read_options;
	config.AddExtensionOption("azure_read_transfer_concurrency",
	                          "Maximum number of threads the Azure client can use for a single parallel read. "
	                          "If azure_read_transfer_chunk_size is less than azure_read_buffer_size then setting "
	                          "this > 1 will allow the Azure client to do concurrent requests to fill the buffer.",
	                          LogicalType::INTEGER, Value::INTEGER(default_read_options.transfer_concurrency));

	config.AddExtensionOption("azure_read_transfer_chunk_size",
	                          "Maximum size in bytes that the Azure client will read in a single request. "
	                          "It is recommended that this is a factor of azure_read_buffer_size.",
	                          LogicalType::BIGINT, Value::BIGINT(default_read_options.transfer_chunk_size));

	config.AddExtensionOption("azure_read_buffer_size",
	                          "Size of the read buffer.  It is recommended that this is evenly divisible by "
	                          "azure_read_transfer_chunk_size.",
	                          LogicalType::UBIGINT, Value::UBIGINT(default_read_options.buffer_size));
}

int64_t AzureStorageFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &hfh = (AzureStorageFileHandle &)handle;
	idx_t max_read = hfh.length - hfh.file_offset;
	nr_bytes = MinValue<idx_t>(max_read, nr_bytes);
	Read(handle, buffer, nr_bytes, hfh.file_offset);
	return nr_bytes;
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

vector<string> AzureStorageFileSystem::Glob(const string &path, FileOpener *opener) {
	if (opener == nullptr) {
		throw InternalException("Cannot do Azure storage Glob without FileOpener");
	}
	auto azure_url = AzureStorageFileSystem::ParseUrl(path);
	auto azure_auth = ParseAzureAuthSettings(opener, path);

	// Azure matches on prefix, not glob pattern, so we take a substring until the first wildcard
	auto first_wildcard_pos = azure_url.path.find_first_of("*[\\");
	if (first_wildcard_pos == string::npos) {
		return {path};
	}

	string shared_path = azure_url.path.substr(0, first_wildcard_pos);
	auto container_client = GetContainerClient(azure_auth, azure_url);

	vector<Azure::Storage::Blobs::Models::BlobItem> found_keys;
	Azure::Storage::Blobs::ListBlobsOptions options;
	options.Prefix = shared_path;
	while (true) {
		Azure::Storage::Blobs::ListBlobsPagedResponse res;
		try {
			res = container_client.ListBlobs(options);
		} catch (Azure::Storage::StorageException &e) {
			throw IOException("AzureStorageFileSystem Read to " + path + " failed with " + e.ErrorCode +
			                  "Reason Phrase: " + e.ReasonPhrase);
		}

		found_keys.insert(found_keys.end(), res.Blobs.begin(), res.Blobs.end());
		if (res.NextPageToken) {
			options.ContinuationToken = res.NextPageToken;
		} else {
			break;
		}
	}

	vector<string> pattern_splits = StringUtil::Split(azure_url.path, "/");
	vector<string> result;
	for (const auto &key : found_keys) {
		vector<string> key_splits = StringUtil::Split(key.Name, "/");
		bool is_match = Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end());

		if (is_match) {
			auto result_full_url = azure_url.prefix + azure_url.container + "/" + key.Name;
			result.push_back(result_full_url);
		}
	}

	return result;
}

// TODO: this code is identical to HTTPFS, look into unifying it
void AzureStorageFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &hfh = (AzureStorageFileHandle &)handle;

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
		auto &sfh = (AzureStorageFileHandle &)*handle;
		if (sfh.length == 0) {
			return false;
		}
		return true;
	} catch (...) {
		return false;
	};
}

void AzureStorageFileSystem::ReadRange(FileHandle &handle, idx_t file_offset, char *buffer_out, idx_t buffer_out_len) {
	auto &afh = (AzureStorageFileHandle &)handle;

	try {
		auto blob_client = *afh.blob_client.GetClient();

		// Specify the range
		Azure::Core::Http::HttpRange range;
		range.Offset = (int64_t)file_offset;
		range.Length = buffer_out_len;
		Azure::Storage::Blobs::DownloadBlobToOptions options;
		options.Range = range;
		options.TransferOptions.Concurrency = afh.read_options.transfer_concurrency;
		options.TransferOptions.InitialChunkSize = afh.read_options.transfer_chunk_size;
		options.TransferOptions.ChunkSize = afh.read_options.transfer_chunk_size;
		auto res = blob_client.DownloadTo((uint8_t *)buffer_out, buffer_out_len, options);

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

void AzureExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string AzureExtension::Name() {
	return "azure";
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void azure_init(duckdb::DatabaseInstance &db) {
	LoadInternal(db);
}

DUCKDB_EXTENSION_API const char *azure_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
