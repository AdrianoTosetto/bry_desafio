#ifndef _TYPES_H_
#define _TYPES_H_

#include <memory>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

struct BIO_deleter { void operator()(BIO* b) { BIO_free(b); } };
struct CMS_ContentInfo_deleter { void operator()(CMS_ContentInfo* c) { CMS_ContentInfo_free(c); } };
struct X509_STORE_deleter { void operator()(X509_STORE* s) { X509_STORE_free(s); } };
struct X509_NAME_deleter {void operator()(X509_NAME* n) { X509_NAME_free(n); }};
struct PKCS7_SIGNER_INFO_deleter {void operator()(PKCS7_SIGNER_INFO* i) { PKCS7_SIGNER_INFO_free(i); }};
struct STACK_OF_X509_deleter { void operator()(STACK_OF(X509)* s) { sk_X509_pop_free(s, X509_free); } };
struct EVP_PKEY_deleter { void operator()(EVP_PKEY* p) { EVP_PKEY_free(p); } };
struct X509_deleter { void operator()(X509* x) { X509_free(x); } };
struct X509_NAME_ENTRY_deleter {void operator()(X509_NAME_ENTRY* entry){ X509_NAME_ENTRY_free(entry); }};
struct ASN1_STRING_deleter {void operator()(ASN1_STRING* entry){ ASN1_STRING_free(entry); }};
struct PKCS12_deleter { void operator()(PKCS12* p) { PKCS12_free(p); } };
struct BufMemDeleter {
    void operator()(BUF_MEM* buf) { BUF_MEM_free(buf); }
};

using BIO_ptr = std::unique_ptr<BIO, BIO_deleter>;
using CMS_ContentInfo_ptr = std::unique_ptr<CMS_ContentInfo, CMS_ContentInfo_deleter>;
using X509_STORE_ptr = std::unique_ptr<X509_STORE, X509_STORE_deleter>;
using X509_NAME_ptr = std::unique_ptr<X509_NAME, X509_NAME_deleter>;
using PKCS7_SIGNER_INFO_ptr = std::unique_ptr<PKCS7_SIGNER_INFO, PKCS7_SIGNER_INFO_deleter>;
using X509_NAME_ENTRY_ptr = std::unique_ptr<X509_NAME_ENTRY, X509_NAME_ENTRY_deleter>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter>;
using X509_ptr = std::unique_ptr<X509, X509_deleter>;
using PKCS12_ptr = std::unique_ptr<PKCS12, PKCS12_deleter>;
using STACK_OF_X509_ptr = std::unique_ptr<STACK_OF(X509), STACK_OF_X509_deleter>;
using ASN1_STRING_ptr = std::unique_ptr<ASN1_STRING, ASN1_STRING_deleter>;
using BufMem_ptr = std::unique_ptr<BUF_MEM, BufMemDeleter>;

struct Error {
    Error(uint8_t ecode, const std::string& ereason): code{ecode}, reason{ereason} {}
    u_int8_t code; 
    const std::string& reason;
};

template <typename ResultT>
struct Result {
    Result(Error e): error{e}, data{std::nullopt}, has_error{true} {};

    Result(ResultT result): data{std::move(result)}, error{std::nullopt}, has_error{false}{};


    std::optional<ResultT> data;
    std::optional<Error> error;
    const bool& has_error;

    // ResultT get_data() const {
    //     return data.value();
    // }

    // Error get_error() const {
    //     return error.value();
    // }
};

struct BytesData {
    BytesData(const unsigned char* b, size_t l): buffer{b}, length{l} {}

    const unsigned char* buffer;
    size_t length;
};

// output type of the function `verify`
struct VerifyResult {
    VerifyResult(bool s, const std::string& cn, const std::string& extracted):
        status{s},
        commom_name{cn},
        extracted_content{extracted} {}

    VerifyResult(): status{false}, commom_name{""} {}

    bool status;
    std::string commom_name;
    std::string extracted_content;
};

#endif