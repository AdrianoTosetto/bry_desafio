#ifndef _HELPERS_H_
#define _HELPERS_H_

#include "types.h"
#include <string>
#include <memory>

Result<BIO_ptr> bio_from_buffer(const unsigned char* buffer, size_t length) {
    BIO* b = BIO_new_mem_buf((const void *) buffer, length);

    if (!b) return Error(0, "Erro ao ler estrutura CMS");

    return BIO_ptr{b};
}

Result<BytesData> bytes_from_bio(BIO *bio) {
    if (!bio) {
        return Error(0, "Invalid BIO pointer");
    }

    size_t len = BIO_ctrl_pending(bio);
    if (len == 0 || len > SIZE_MAX) {
        return Error(0, "Invalid data size in BIO");
    }

    unsigned char *buffer = static_cast<unsigned char*>(malloc(len));
    if (!buffer) {
        return Error(0, "Memory allocation failed");
    }

    int read_bytes = BIO_read(bio, buffer, static_cast<int>(len));
    if (read_bytes <= 0) {
        free(buffer);
        return Error(0, "Failed to read from BIO");
    }

    return BytesData(buffer, static_cast<size_t>(read_bytes));
}

BytesData encode_base64(const unsigned char* buffer, size_t length) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    BUF_MEM* buffer_ptr;

    bio = BIO_push(b64, bio);
    

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    const unsigned char* data = (const unsigned char*) (*buffer_ptr).data;

    return {data, length};
}

std::string asn1_to_ascii_via_bio(ASN1_STRING *asn1_str) {
    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_STRING_print_ex(bio, asn1_str, ASN1_STRFLGS_RFC2253);
    
    char buffer[1024];
    int len = BIO_read(bio, buffer, sizeof(buffer));
    std::string ascii_str(buffer, len);
    
    BIO_free(bio);
    return ascii_str;
}

Result<std::string> cn_from_p7(PKCS7 *p7) {
    if (!PKCS7_type_is_signed(p7)) {
        return Error(0, "No signature found in the file");
    }

    STACK_OF(PKCS7_SIGNER_INFO) *signers = PKCS7_get_signer_info(p7);
    if (!signers || sk_PKCS7_SIGNER_INFO_num(signers) == 0) {
        return Error(0, "No signers found in the file");
    }

    for (int i = 0; i < sk_PKCS7_SIGNER_INFO_num(signers); i++) {
        PKCS7_SIGNER_INFO* signer = sk_PKCS7_SIGNER_INFO_value(signers, i);
        if (!signer) continue;

        X509* signer_cert = PKCS7_cert_from_signer_info(p7, signer);
        if (!signer_cert) continue;

        std::unique_ptr<X509, decltype(&X509_free)> cert_guard(signer_cert, X509_free);

        X509_NAME* subject = X509_get_subject_name(signer_cert);
        if (!subject) continue;

        int cn_loc = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        if (cn_loc < 0) continue;

        X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(subject, cn_loc);
        if (!cn_entry) continue;

        ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
        if (!cn_asn1) continue;

        std::string cn = asn1_to_ascii_via_bio(cn_asn1);
        
        if (!cn.empty()) {
            return Result<std::string>(cn);
        }
    }
    
    return Error(0, "No CN found in any signer");
}

std::string sha512(const std::string &input) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha512();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Inicializa o contexto e calcula o hash
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

#endif