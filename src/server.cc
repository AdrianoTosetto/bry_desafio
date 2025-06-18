#include <iostream>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include "actions.h"
#include "helpers.h"
#include "middlewares.h"
#include "../include/json.h"
#include "../include/httplib.h"

using json = nlohmann::json;
using const_str = const std::string&;

int main() {
    httplib::Server svr;

    // Configuração do CORS (importante para testes com Insomnia/Postman)
    svr.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "POST, GET, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });

    svr.Post("/signature", [](const httplib::Request& req, httplib::Response& res) {

        // valida parametros necessarios do body
        bool validated = signature_endpoint_fields_validator(req, res);

        if (!validated) return;

        const auto& file = req.get_file_value("arquivo");
        const auto& cert_file = req.get_file_value("cert");
        const std::string& password = req.get_file_value("password").content;

        auto result = create_attached_signature(
            (unsigned char *) file.content.data(),
            file.content.size(),
            BytesData((const unsigned char *) cert_file.content.data(), cert_file.content.length()),
            password
        );

        if (result.has_error) {
            auto error = result.error.value();
            const auto& response = str_to_json_error(error.reason);

            res.status = 400;
            res.set_content(response.dump(), "text/plain");
        }

        // bytes do arquivo assinado
        auto bytes_data = result.data.value();
        BIO_ptr out_bio(BIO_new_file("./../output/arquivo_assinado.p7s", "wb"));

        BIO_write(out_bio.get(), bytes_data.buffer, bytes_data.length);

        const std::string& base64 = (const char*) encode_base64(bytes_data.buffer, bytes_data.length).buffer;

        json response_json = {
            {"signed_file_base64", base64}
        };

        res.set_content(response_json.dump(), "text/plain");

    });

    svr.Post("/verify", [](const httplib::Request& req, httplib::Response& res) {

        // valida o campo necessario do body
        bool validated = verify_endpoint_fields_validator(req, res);

        if (!validated) return;

        const auto& file = req.get_file_value("arquivo_assinado");
        const unsigned char* p7s_file_raw_data = (const unsigned char*) file.content.data();
        
        const auto& verify_result = verify_attached_signature(BytesData(p7s_file_raw_data, file.content.length()));
        

        if (verify_result.has_error) {
            const auto& error = verify_result.error.value();

            json response = str_to_json_error(error.reason);

            res.status = 400;
            res.set_content(response.dump(), "text/plain");
            return;
        }

        auto verified = verify_result.data.value();

        const auto cn = verify_result.data.value().commom_name;
        const auto extracted_data = verify_result.data.value().extracted_content;
    
        json response_json = 
            {
                {"Status", verified.status ? "Valid" : "Invalid"},
                {"CN", cn},
                {"Extracted", extracted_data}
            };

        res.set_content(response_json.dump(), "text/plain");
        res.status = 200;
        return;
    });

    // Rota OPTIONS para CORS (necessário para alguns clientes)
    svr.Options("/signature", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
    });
    svr.Options("/verify", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
    });

    std::cout << "Servidor rodando na porta 8080...\n";
    svr.listen("0.0.0.0", 8080);

    return 0;
}