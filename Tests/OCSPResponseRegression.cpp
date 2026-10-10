#include "ocsp_response.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

static std::vector<unsigned char> encode(OCSP_RESPONSE *response) {
	unsigned char *data = nullptr;
	int size = i2d_OCSP_RESPONSE(response, &data);
	assert(size > 0);
	std::vector<unsigned char> result(data, data + size);
	OPENSSL_free(data);
	return result;
}

int main() {
	EVP_PKEY *key = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", 2048);
	assert(key);
	X509 *cert = X509_new();
	assert(cert);
	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_getm_notBefore(cert), -60);
	X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
	X509_set_pubkey(cert, key);
	X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
		(const unsigned char *)"OCSP regression", -1, -1, 0);
	X509_set_issuer_name(cert, X509_get_subject_name(cert));
	assert(X509_sign(cert, key, EVP_sha256()) > 0);
	OCSP_CERTID *id = OCSP_cert_to_id(nullptr, cert, cert);
	assert(id);
	ASN1_TIME *now = ASN1_TIME_set(nullptr, time(nullptr));
	ASN1_TIME *next = ASN1_TIME_set(nullptr, time(nullptr) + 3600);
	for (int expected : {V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED, V_OCSP_CERTSTATUS_UNKNOWN}) {
		OCSP_BASICRESP *basic = OCSP_BASICRESP_new();
		assert(OCSP_basic_add1_status(basic, id, expected, OCSP_REVOKED_STATUS_KEYCOMPROMISE,
			expected == V_OCSP_CERTSTATUS_REVOKED ? now : nullptr, now, next));
		assert(OCSP_basic_sign(basic, cert, key, EVP_sha256(), nullptr, 0));
		OCSP_RESPONSE *response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
		auto bytes = encode(response);
		for (int repeat = 0; repeat < 1000; ++repeat) {
			assert(ZSignOCSPStatus(bytes.data(), bytes.size(), id) == expected);
		}
		for (size_t length = 0; length < bytes.size(); ++length) {
			assert(ZSignOCSPStatus(bytes.data(), length, id) == V_OCSP_CERTSTATUS_UNKNOWN);
		}
		bytes.push_back(0);
		assert(ZSignOCSPStatus(bytes.data(), bytes.size(), id) == V_OCSP_CERTSTATUS_UNKNOWN);
		OCSP_RESPONSE_free(response);
		OCSP_BASICRESP_free(basic);
	}
	for (int responseStatus : {OCSP_RESPONSE_STATUS_SUCCESSFUL, OCSP_RESPONSE_STATUS_TRYLATER}) {
		OCSP_RESPONSE *response = OCSP_response_create(responseStatus, nullptr);
		auto bytes = encode(response);
		assert(ZSignOCSPStatus(bytes.data(), bytes.size(), id) == V_OCSP_CERTSTATUS_UNKNOWN);
		OCSP_RESPONSE_free(response);
	}
	const unsigned char junk[] = "not an OCSP response";
	assert(ZSignOCSPStatus(junk, sizeof(junk), id) == V_OCSP_CERTSTATUS_UNKNOWN);
	assert(ZSignOCSPStatus(nullptr, 0, id) == V_OCSP_CERTSTATUS_UNKNOWN);
	ASN1_TIME_free(now);
	ASN1_TIME_free(next);
	OCSP_CERTID_free(id);
	X509_free(cert);
	EVP_PKEY_free(key);
	puts("OCSP response regression passed");
}
