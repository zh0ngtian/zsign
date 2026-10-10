#pragma once

#include <openssl/ocsp.h>
#include <memory>

// A decoder must never receive an uninitialized output pointer. Treat malformed
// responses and missing certificate statuses as unknown, not as revocation.
inline int ZSignOCSPStatus(const unsigned char *bytes, long length, OCSP_CERTID *certID) {
	if (!bytes || length <= 0 || !certID) return V_OCSP_CERTSTATUS_UNKNOWN;
	const unsigned char *cursor = bytes;
	std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)> response(
		d2i_OCSP_RESPONSE(nullptr, &cursor, length), OCSP_RESPONSE_free);
	if (!response || cursor != bytes + length ||
		OCSP_response_status(response.get()) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		return V_OCSP_CERTSTATUS_UNKNOWN;
	}
	std::unique_ptr<OCSP_BASICRESP, decltype(&OCSP_BASICRESP_free)> basic(
		OCSP_response_get1_basic(response.get()), OCSP_BASICRESP_free);
	if (!basic) return V_OCSP_CERTSTATUS_UNKNOWN;
	int status = V_OCSP_CERTSTATUS_UNKNOWN;
	if (!OCSP_resp_find_status(basic.get(), certID, &status, nullptr, nullptr, nullptr, nullptr)) {
		return V_OCSP_CERTSTATUS_UNKNOWN;
	}
	return status;
}
