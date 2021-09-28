#include <string>
#include <iostream>

namespace tst{

    struct SERVER{};
    struct CLIENT{};

    template <typename T>
    class Cls {};

    template <>
    class Cls <tst::SERVER>{

    public:

        int aa, bb;

        Cls(int aa, int bb): aa(aa), bb(bb) { std::cout << "server\n"; }

        void f() { std::cout << "server f\n"; }
    };

    template <>
    class Cls <tst::CLIENT>{

    public:

        float c;

        Cls(std::string str) { std::cout << "client\n"; }

        int g() { std::cout << "client g\n"; return 0; }
    };
}

int main(){

    tst::Cls <tst::SERVER> server(2, 3);
    tst::Cls <tst::CLIENT> client("ceva");

    server.f();
    client.g();

    return 0;
}