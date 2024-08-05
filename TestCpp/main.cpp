#include <iostream>
#include <bech32.h>

void test1() {
    char bstr[] = "age1c6j0mssdmznty6ahkckmhwszhd3lquupd5rqxnzlucma482yvspsengc59";
    bech32::DecodedResult decodedResult = bech32::decode(bstr);
}

int main() {
    test1();

    return 0;
}