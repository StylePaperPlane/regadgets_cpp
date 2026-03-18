#include <regadgets/regadgets.hpp>
#include <iostream>
int main(){
    using namespace regadgets;

    auto data = from_string("hello");
    auto b64 = encode_b64(data);
    auto digest = to_hex(sha256(data));

    auto res = decode_b64(b64);

    std::cout<<digest<<"\n "<<to_string(res);
    return 0;
}