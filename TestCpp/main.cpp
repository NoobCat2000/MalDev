#include <json.hpp>
#include <iostream>

using json = nlohmann::json;

void test2() {
    json j;
    j["name"] = "Hello.docx";
    j["mimeType"] = "application/octet-stream";
    j["parents"] = { "01234" };
    std::cout << j.dump() << std::endl;
}

int main() {
    test2();

    return 0;
}