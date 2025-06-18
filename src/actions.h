#ifndef __UTILS_H__
#define __UTILS_H__

#include <openssl/pkcs12.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <iostream>
#include <openssl/rsa.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <fstream>
#include <vector>
#include <sstream>
#include <memory>
#include <optional>
#include <inttypes.h>
#include "types.h"
#include "helpers.h"

Result<VerifyResult> verify_attached_signature(BytesData p7_file) {
    PKCS7 *p7 = d2i_PKCS7(nullptr, &p7_file.buffer, p7_file.length);

    if (!p7)
        return Error(0, std::string("Error while reading PKCS#7 ") + std::string(ERR_error_string(ERR_get_error(), nullptr)));

    if (!PKCS7_type_is_signed(p7))
        return Error(0, "P7 file given is not a signed file");


    BIO* out = BIO_new(BIO_s_mem());
    
    if (!out) return Error(0, "Error while creating BIO");
    
    int result = PKCS7_verify(p7, nullptr, nullptr, nullptr, out, PKCS7_NOVERIFY);

    // assinatura invalida, retorna VerifyResult com status `false`
    if (result != 1) return VerifyResult{};

    const auto& get_cn_result = cn_from_p7(p7);
    const auto& cn = get_cn_result.has_error ? "" : get_cn_result.data.value();

    const char* extracted_content;
    auto len = BIO_get_mem_data(out, &extracted_content);
    return VerifyResult(true, get_cn_result.data.value(), sha512({extracted_content, len}));
}

Result<BytesData> create_attached_signature(
    const unsigned char* content,
    size_t content_length,
    BytesData cert,
    const std::string& password
) {

    const auto& bio_result = bio_from_buffer(content, content_length);

    if (bio_result.has_error) {
        return bio_result.error.value();
    }

    const auto& content_bio = bio_result.data.value();

    const auto flags = CMS_PARTIAL | CMS_STREAM;
    CMS_ContentInfo_ptr cms(CMS_sign(nullptr, nullptr, nullptr, nullptr, flags));

    if (!cms) {
        std::cerr << "Erro ao criar estrutura CMS" << std::endl;
        ERR_print_errors_fp(stderr);
        return Error(0, "Erro ao ler estrutura CMS");
    }

    PKCS12_ptr p12(d2i_PKCS12(NULL, &cert.buffer, cert.length));
    EVP_PKEY* private_key = nullptr;
    X509* cert509 = nullptr;
    STACK_OF(X509)* ca = nullptr;

    if (!PKCS12_parse(p12.get(), password.c_str(), &private_key, &cert509, &ca)) {
        ERR_print_errors_fp(stderr);
        return Error(0, "Error while reading PKCS#12)");
    }

    if (!CMS_add1_signer(cms.get(), cert509, private_key, EVP_sha512(), CMS_BINARY)) {
        std::cerr << "Erro ao adicionar signatário" << std::endl;
        ERR_print_errors_fp(stderr);
        return Error(0, "Erro ao ler estrutura CMS");
    }

    // CMS_add1_signingTime(CMS_get0_SignerInfos(cms.get())[0], nullptr);

    if (CMS_final(cms.get(), content_bio.get(), nullptr, CMS_STREAM) != 1) {
        std::cerr << "Erro ao finalizar assinatura" << std::endl;
        ERR_print_errors_fp(stderr);
        return Error(0, "Erro ao finalizar assinatura");
    }

    BIO_ptr p7_bio(BIO_new(BIO_s_mem()));

    if (i2d_CMS_bio(p7_bio.get(), cms.get()) != 1) return Error(0, "Erro ao escrever assinatura");

    return bytes_from_bio(p7_bio.get());
}


#endif