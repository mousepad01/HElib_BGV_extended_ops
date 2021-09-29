#include <iostream>
#include <type_traits>

/**
 * For this test, murmur3 hash function is used, with different seeds to emulate multiple hash functions
 * The source code and header is not inlcluded in this repository
 * (as of september 2021, it can be found at https://github.com/aappleby/smhasher - version used from commit on january 9 2016)
**/
#include "MurmurHash3.h"
#include "helib_extended_ops.h"

/**
 * Generating functions at compile time imspired by 
 * https://www.codeproject.com/Articles/857354/Compile-Time-Loops-with-Cplusplus-Creating-a-Gener
**/

template <uint32_t HASH_FUNCTION_COUNT, uint32_t ELEMENT_COUNT>
class TestBloomFilter{

    const uint32_t RND_CNT;
    const double FALSE_POSITIVE_RATE;

    long p;
    long m;
    long r;
    long bits;
    long c;
    std::vector<long> mvec;
    std::vector<long> gens;
    std::vector<long> ords;

    helib::Context * context;
    const helib::PubKey & pk;
    const helib::SecKey & sk;
    const helib::EncryptedArray & ea;
    std::vector<helib::zzX> unpackSlotEncoding;
    long nslots;

    std::vector <std::function <uint32_t(const void *, size_t)>> hash_functions;

    // constants taken from sha256 constants, but could be any other
    static constexpr uint32_t SEED[64] = \
        { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

    static uint32_t murmur3_wrap(const void * element, size_t len, uint32_t seed, uint32_t element_count) {

        uint32_t hash[4];
        MurmurHash3_x64_128(element, len, seed, (void *)hash);

        return hash[0] % element_count;
    }

    void hash_function_generator(std::integral_constant <int, HASH_FUNCTION_COUNT>) {}

    template <int seed_index = 0>
    void hash_function_generator(std::integral_constant <int, seed_index> = std::integral_constant <int, 0>()){

        this->hash_functions.push_back(std::function <uint32_t(const void *, size_t len)> ([](const void * element, size_t len) {
                return murmur3_wrap(element, len, SEED[seed_index], ELEMENT_COUNT);
        }));

        hash_function_generator(std::integral_constant <int, seed_index + 1>());
    }

    TestBloomFilter(const uint32_t RND_CNT, const double FALSE_POSITIVE_RATE, 
                    long p, long m, long r, long bits, long c,
                    std::vector<long> mvec, std::vector<long> gens, std::vector<long> ords, 
                    helib::Context * context, const helib::SecKey & sk, const helib::EncryptedArray & ea): 
                    RND_CNT(RND_CNT), FALSE_POSITIVE_RATE(FALSE_POSITIVE_RATE),
                    p(p), m(m), r(r), c(c), bits(bits), mvec(mvec), gens(gens), ords(ords), 
                    context(context), sk(sk), ea(ea), pk(sk) {

        helib::buildUnpackSlotEncoding(this->unpackSlotEncoding, this->ea);

        this->nslots = this->ea.size();

        this->hash_function_generator();
    }

public:

    static TestBloomFilter * makeTest(const uint32_t RND_CNT, const double FALSE_POSITIVE_RATE) {
        
        long p = 2;
        long m = 4095;
        long r = 1;
        long bits = 500;
        long c = 2;

        std::vector<long> mvec = {7, 5, 9, 13};
        std::vector<long> gens = {2341, 3277, 911};
        std::vector<long> ords = {6, 4, 6};

        helib::Context * context = helib::ContextBuilder<helib::BGV>()
                                    .m(2)
                                    .p(p)
                                    .r(r)
                                    .gens(gens)
                                    .ords(ords)
                                    .bits(bits)
                                    .c(c)
                                    .bootstrappable(true)
                                    .mvec(mvec)
                                    .buildPtr();   

        helib::SecKey * sk = new helib::SecKey(*context);
        sk->GenSecKey();
        sk->genRecryptData();

        TestBloomFilter * test = new TestBloomFilter(RND_CNT, FALSE_POSITIVE_RATE, 
                                                        p, m, r, bits, c, mvec, gens, ords, 
                                                        context, *sk, context->getEA());

        std::cout << "Parameter selection for HElib-BGV\n \
(note that from the point of view of the bloom filter utilisation,\n \
only the addition to the filter and query decryption require client-side cryptograhpic operations,\n \
the query request itself doest not need (and cannot be) encrypted, \n \
and the elements themselves are also never encrypted because they never interact with the server):\n \
Prime modulus P = p^1 = 2 (necessary),\n \
Cyclotomic polynomial dimension = " << m << "(provides " << test->nslots << " slots)\n \
Number of bits of the modulus chain = " << bits << "\n \
Bootstrapping and key-switching data is also generated but most likely not needed\n";

        return test;
    }

    ~TestBloomFilter(){

        delete &sk;
        delete context;
    }

    void go() {

        std::cout << "Executing small test with " << this->RND_CNT << " rounds...\n";
    }
};



int main(){

    int test_type;
    std::cout << \
"There are 2 types of tests\n \
Both tests select a number of random elements, insert them in an encrypted set represented by a bloom filter,\n \
and then execute queries with other random elements, that can return either\n \
\"DEFINETLY NOT IN THE SET\" or \"PROBABLY IN THE SET\"\n \
Both tests should provide the false positive probability up to ~0.1%\n \
The small test filter contains 100 elements and executes 5 queries\n \
The big test filter contains 10000 elements and executes 100 queries\n \
small test [1] / big test [2] ?\n";
    std::cin >> test_type;

    uint32_t test_round_cnt;
    std::cout << "How many times to repeat the test (each time new elements and queries) ?\n";
    std::cin >> test_round_cnt;

    if(test_type == 1){

        TestBloomFilter <10, 100> * test = TestBloomFilter<10, 100>::makeTest(test_round_cnt, 0.1);
        test->go();

        delete test;
    }
    else{

        TestBloomFilter <6, 10000> * test = TestBloomFilter<6, 10000>::makeTest(test_round_cnt, 0.1);
        test->go();

        delete test;
    }

    return 0;
}