#ifndef _MIDDLEWARES_H_
#define _MIDDLEWARES_H_

#include "../include/json.h"
#include "../include/httplib.h"

using Handler = std::function<bool(const httplib::Request &, httplib::Response &)>;
using json = nlohmann::json;

json str_to_json_error(const std::string& error) {
    json json_error = {
        {"Error", error}
    };

    return json_error;
}

Handler create_fields_validator(const std::vector<std::pair<std::string, std::string>> fields) {

    return [fields](const httplib::Request& req, httplib::Response& res) {
        for (const auto& f : fields) {
            if (!req.has_file(f.first)) {
                json response = 
                    str_to_json_error(f.second);
            
                res.status = 400;
                res.set_content(response.dump(), "text/plain");

                return false;
            }
        }

        return true;
    };
}

Handler signature_endpoint_fields_validator = create_fields_validator({
    {"cert", "PCKCS12 certificate `cert` is necessary. Please send it as a named parameter `cert`"},
    {"arquivo", "File `arquivo` is necessary. Please send it as a named parameter `arquivo`"},
    {"password", "Password string is necessary. Please send it as a named parameter `password`"},
});

Handler verify_endpoint_fields_validator = create_fields_validator({
    {"arquivo_assinado", "Signed file is necessary. Please send it as a named parameter `arquivo_assinado`"},
});


#endif