#pragma once

#include "duckdb/common/http_state.hpp"
#include <azure/core/context.hpp>
#include <azure/core/http/http.hpp>
#include <azure/core/http/policies/policy.hpp>
#include <azure/core/http/raw_response.hpp>
#include <memory>

namespace duckdb {

class HttpStatePolicy : public Azure::Core::Http::Policies::HttpPolicy {
public:
	HttpStatePolicy(std::shared_ptr<HTTPState> http_state);

	std::unique_ptr<Azure::Core::Http::RawResponse> Send(Azure::Core::Http::Request &request,
	                                                     Azure::Core::Http::Policies::NextHttpPolicy next_policy,
	                                                     Azure::Core::Context const &context) const override;

	std::unique_ptr<Azure::Core::Http::Policies::HttpPolicy> Clone() const override;

private:
	std::shared_ptr<HTTPState> http_state;
};

} // namespace duckdb
