#include "auth/azure_device_code_function.hpp"
#include "auth/azure_device_codes_context.hpp"
#include "azure_storage_account_client.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/assert.hpp"
#include "duckdb/common/enums/vector_type.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/string_type.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/function.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_data.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include <chrono>
#include <memory>
#include <utility>

namespace duckdb {

struct AzureDeviceCodeBindData : public FunctionData {
	const std::string secret_name;

	AzureDeviceCodeBindData(std::string secret_name) : secret_name(std::move(secret_name)) {
	}

	duckdb::unique_ptr<FunctionData> Copy() const override {
		return make_uniq<AzureDeviceCodeBindData>(secret_name);
	}

	bool Equals(const FunctionData &other_p) const override {
		if (&other_p == this)
			return true;
		auto &other = other_p.Cast<AzureDeviceCodeBindData>();
		return other.secret_name == this->secret_name;
	}
};

struct AzureDeviceCodeCompleted : public GlobalTableFunctionState {
	AzureDeviceCodeCompleted() : completed(false) {
	}

	bool completed;
};

static void AzureDeviceCodeImplementation(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<AzureDeviceCodeBindData>();
	auto &global_data = data.global_state->Cast<AzureDeviceCodeCompleted>();

	if (global_data.completed) {
		return;
	}

	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto secret = context.db->config.secret_manager->GetSecretByName(transaction, bind_data.secret_name);
	if (!secret) {
		throw InvalidInputException("azure_devicecode no secret found named %s", bind_data.secret_name);
	}

	auto device_code_credential = CreateDeviceCodeCredential(ClientData::Get(context).file_opener.get(),
	                                                         dynamic_cast<const KeyValueSecret &>(*secret->secret));
	auto device_code_info = device_code_credential->RequestDeviceCode();

	auto &device_code_context = context.registered_state[AzureDeviceCodesClientContextState::CONTEXT_KEY];
	if (!device_code_context) {
		device_code_context = make_shared<AzureDeviceCodesClientContextState>();
	}

	D_ASSERT(reinterpret_cast<AzureDeviceCodesClientContextState *>(device_code_context.get()) != nullptr);
	reinterpret_cast<AzureDeviceCodesClientContextState &>(*device_code_context)
	    .device_code_info_by_secret.insert(std::make_pair(bind_data.secret_name, device_code_info));

	output.SetCapacity(1);
	output.SetValue(0, 0, bind_data.secret_name);
	output.SetValue(1, 0, device_code_info.user_code);
	output.SetValue(2, 0, device_code_info.verification_uri);
	output.SetValue(3, 0, device_code_info.message);
	auto expires_at = std::chrono::duration_cast<std::chrono::seconds>(device_code_info.expires_at.time_since_epoch());
	output.SetValue(4, 0, Value::TIMESTAMP(Timestamp::FromEpochSeconds(expires_at.count())));
	output.SetCardinality(1);
	global_data.completed = true;
}

static unique_ptr<FunctionData> AzureDeviceCodeBind(ClientContext &context, TableFunctionBindInput &input,
                                                    vector<LogicalType> &return_types, vector<string> &names) {
	if (input.inputs.empty()) {
		throw BinderException("azure_devicecode takes at least one argument");
	}
	if (input.inputs[0].IsNull()) {
		throw BinderException("azure_devicecode first parameter cannot be NULL");
	}

	auto secret_name = StringValue::Get(input.inputs[0]);

	names.emplace_back("secret_name");
	return_types.emplace_back(LogicalType::VARCHAR);

	names.emplace_back("user_code");
	return_types.emplace_back(LogicalType::VARCHAR);

	names.emplace_back("verification_uri");
	return_types.emplace_back(LogicalType::VARCHAR);

	names.emplace_back("message");
	return_types.emplace_back(LogicalType::VARCHAR);

	names.emplace_back("expires_in");
	return_types.emplace_back(LogicalType::TIMESTAMP);

	return make_uniq<AzureDeviceCodeBindData>(secret_name);
}

unique_ptr<GlobalTableFunctionState> AzureDeviceCodeInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<AzureDeviceCodeCompleted>();
}

void RegisterAzureDeviceCodeFunction(DatabaseInstance &instance) {

	TableFunction azure_devicecode("azure_devicecode", {LogicalType::VARCHAR}, AzureDeviceCodeImplementation,
	                               AzureDeviceCodeBind, AzureDeviceCodeInit);
	ExtensionUtil::RegisterFunction(instance, azure_devicecode);
}
} // namespace duckdb
