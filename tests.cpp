#include <iostream>

#include "helib_extended_ops.h"

using namespace heExtension;

int lev_dist(std::vector <int> & fst, std::vector <int> & snd){

    int n = fst.size();
    int m = snd.size();

    int * d_prev = new int[m + 1];
    int * d = new int[m + 1];

    for(int j = 0; j <= m; j++){

        d_prev[j] = j;
        d[j] = d_prev[j];
    }
        
    for(int i = 1; i <= n; i++){

        d[0] = i;
        for(int j = 1; j <= m; j++){

            int val0 = (fst[i - 1] != snd[j - 1]) + d_prev[j - 1];
            int val1 = d_prev[j] + 1;
            int val2 = d[j - 1] + 1;

            int m1 = val1 < val2 ? val1 : val2;
            d[j] = val0 < m1 ? val0 : m1;
            
            d_prev[j - 1] = d[j - 1]; // prepare for the next value of i
        }
        d_prev[m] = d[m];
    }

    return d[m];
}

void test_eq_gt(){

    // Plaintext prime modulus.
    long p = 2;
    // Cyclotomic polynomial - defines phi(m).
    long m = 4095;
    // Hensel lifting (default = 1).
    long r = 1;
    // Number of bits of the modulus chain.
    long bits = 500;
    // Number of columns of Key-Switching matrix (typically 2 or 3).
    long c = 2;
    // Factorisation of m required for bootstrapping.
    std::vector<long> mvec = {7, 5, 9, 13};
    // Generating set of Zm* group.
    std::vector<long> gens = {2341, 3277, 911};
    // Orders of the previous generators.
    std::vector<long> ords = {6, 4, 6};

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .build();

    // Create a secret key associated with the context.
    helib::SecKey secret_key(context);
    // Generate the secret key.
    secret_key.GenSecKey();

    // Generate bootstrapping data.
    secret_key.genRecryptData();

    // Public key management.
    // Set the secret key (upcast: SecKey is a subclass of PubKey).
    const helib::PubKey & public_key = secret_key;

    // Get the EncryptedArray of the context.
    const helib::EncryptedArray & ea = context.getEA();

    // Build the unpack slot encoding.
    std::vector<helib::zzX> unpackSlotEncoding;
    buildUnpackSlotEncoding(unpackSlotEncoding, ea);

    // Get the number of slot (phi(m)).
    long nslots = ea.size();

    for(int tst = 0; tst < 30; tst++){

        long bitsize = rand() % 20 + 10;
        long bitmask = ((uint64_t)1 << bitsize) - 1;

        uint64_t * a = new uint64_t[nslots];
        uint64_t * b = new uint64_t[nslots];

        for(int i = 0; i < nslots; i++){

            a[i] = (rand() | (rand() >> 16)) & bitmask;

            if(rand() & 0x01)
                b[i] = a[i];
            else
                b[i] = (rand() | (rand() >> 16)) & bitmask;
        }

        helib::Ctxt empty(public_key);
        std::vector <helib::Ctxt> enc_a_aux(bitsize, empty); // vector de biti dintr un ctxt
        std::vector <helib::Ctxt> enc_b_aux(bitsize, empty);

        for(int i = 0; i < bitsize; i++){

            std::vector <long> ai_allslots;
            std::vector <long> bi_allslots;
            
            for(int j = 0; j < nslots; j++){

                ai_allslots.push_back((a[j] >> i) & 0x01);
                bi_allslots.push_back((b[j] >> i) & 0x01);
            }

            ea.encrypt(enc_a_aux[i], public_key, ai_allslots);
            ea.encrypt(enc_b_aux[i], public_key, bi_allslots);
        }

        helib::CtPtrs_vectorCt enc_a(enc_a_aux);
        helib::CtPtrs_vectorCt enc_b(enc_b_aux);

        helib::Ctxt eq_res = (enc_a != enc_b);

        helib::Ptxt <helib::BGV> dec_eq(context);
        secret_key.Decrypt(dec_eq, eq_res);

        helib::Ctxt gt_res = (enc_a > enc_b);

        helib::Ptxt <helib::BGV> dec_gt(context);
        secret_key.Decrypt(dec_gt, gt_res);

        for(int i = 0; i < nslots; i++){

            if(dec_eq.at(i).getData() != (a[i] != b[i]))
                std::cout << "eq err at " << i << "\n";

            if(dec_gt.at(i).getData() != (a[i] > b[i]))
                std::cout << "gt err at " << i << "\n";
        }
            
    }

    std::cout << "done\n";
}

void test_if_then_else(){

    // Plaintext prime modulus.
    long p = 2;
    // Cyclotomic polynomial - defines phi(m).
    long m = 4095;
    // Hensel lifting (default = 1).
    long r = 1;
    // Number of bits of the modulus chain.
    long bits = 500;
    // Number of columns of Key-Switching matrix (typically 2 or 3).
    long c = 2;
    // Factorisation of m required for bootstrapping.
    std::vector<long> mvec = {7, 5, 9, 13};
    // Generating set of Zm* group.
    std::vector<long> gens = {2341, 3277, 911};
    // Orders of the previous generators.
    std::vector<long> ords = {6, 4, 6};

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .build();

    // Create a secret key associated with the context.
    helib::SecKey secret_key(context);
    // Generate the secret key.
    secret_key.GenSecKey();

    // Generate bootstrapping data.
    secret_key.genRecryptData();

    // Public key management.
    // Set the secret key (upcast: SecKey is a subclass of PubKey).
    const helib::PubKey& public_key = secret_key;

    // Get the EncryptedArray of the context.
    const helib::EncryptedArray& ea = context.getEA();

    // Build the unpack slot encoding.
    std::vector<helib::zzX> unpackSlotEncoding;
    buildUnpackSlotEncoding(unpackSlotEncoding, ea);

    // Get the number of slot (phi(m)).
    long nslots = ea.size();

    for(int tst = 0; tst < 30; tst++){

        long bitsize = rand() % 20 + 10;
        long bitmask = ((uint64_t)1 << bitsize) - 1;

        uint64_t * a = new uint64_t[nslots];
        uint64_t * b = new uint64_t[nslots];

        for(int i = 0; i < nslots; i++){

            a[i] = (rand() | (rand() >> 16)) & bitmask;

            if(rand() & 0x01)
                b[i] = a[i];
            else
                b[i] = (rand() | (rand() >> 16)) & bitmask;
        }

        helib::Ctxt empty(public_key);
        std::vector <helib::Ctxt> enc_a_aux(bitsize, empty); // vector de biti dintr un ctxt
        std::vector <helib::Ctxt> enc_b_aux(bitsize, empty);

        for(int i = 0; i < bitsize; i++){

            std::vector <long> ai_allslots;
            std::vector <long> bi_allslots;
            
            for(int j = 0; j < nslots; j++){

                ai_allslots.push_back((a[j] >> i) & 0x01);
                bi_allslots.push_back((b[j] >> i) & 0x01);
            }

            ea.encrypt(enc_a_aux[i], public_key, ai_allslots);
            ea.encrypt(enc_b_aux[i], public_key, bi_allslots);
        }

        helib::CtPtrs_vectorCt enc_a(enc_a_aux);
        helib::CtPtrs_vectorCt enc_b(enc_b_aux);

        std::vector <helib::Ctxt> max_ab_aux = if_then_else(enc_a > enc_b, enc_a, enc_b);
        helib::CtPtrs_vectorCt max_ab(max_ab_aux);

        std::vector <long> dec_max;
        helib::decryptBinaryNums(dec_max, max_ab, secret_key, ea, false, true);

        for(int i = 0; i < nslots; i++){

            if(dec_max[i] != (a[i] > b[i] ? a[i] : b[i]))
                std::cout << "if_then_else err at " << i << "\n";
        }
    }

    std::cout << "done\n";
}

void test_lev_dist(){

    std::string a, b;
    std::cin >> a >> b;

    std::vector <int> va(a.size());
    std::vector <int> vb(b.size());

    for(int i = 0; i < a.size(); i++)
        va[i] = static_cast <int> (a[i]);

    for(int i = 0; i < b.size(); i++)
        vb[i] = static_cast <int> (b[i]);

    std::cout << "plaintext lev dist: " << lev_dist(va, vb) << "\n";

    // Plaintext prime modulus.
    long p = 2;
    // Cyclotomic polynomial - defines phi(m).
    long m = 4095;
    // Hensel lifting (default = 1).
    long r = 1;
    // Number of bits of the modulus chain.
    long bits = 500;
    // Number of columns of Key-Switching matrix (typically 2 or 3).
    long c = 2;
    // Factorisation of m required for bootstrapping.
    std::vector<long> mvec = {7, 5, 9, 13};
    // Generating set of Zm* group.
    std::vector<long> gens = {2341, 3277, 911};
    // Orders of the previous generators.
    std::vector<long> ords = {6, 4, 6};

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .thickboot()
                               .build();

    // Create a secret key associated with the context.
    helib::SecKey secret_key(context);
    // Generate the secret key.
    secret_key.GenSecKey();

    // Generate bootstrapping data.
    secret_key.genRecryptData();

    helib::addSome1DMatrices(secret_key);
    helib::addFrbMatrices(secret_key);

    // Public key management.
    // Set the secret key (upcast: SecKey is a subclass of PubKey).
    const helib::PubKey& public_key = secret_key;

    // Get the EncryptedArray of the context.
    const helib::EncryptedArray& ea = context.getEA();

    long nslots = ea.size();

    const int CHAR_BITLEN = 8;

    helib::Ctxt empty_ctxt(public_key);
    std::vector <helib::Ctxt> empty(CHAR_BITLEN, empty_ctxt);

    std::vector <std::vector <helib::Ctxt>> fst_raw(va.size(), empty);
    std::vector <std::vector <helib::Ctxt>> snd_raw(vb.size(), empty);

    for(int i = 0; i < va.size(); i++){
        for(int j = 0; j < CHAR_BITLEN; j++){

            std::vector <long> bit_enc(nslots, (va[i] >> j) & 0x01);
            ea.encrypt(fst_raw[i][j], public_key, bit_enc);
        }
    }

    for(int i = 0; i < vb.size(); i++){
        for(int j = 0; j < CHAR_BITLEN; j++){

            std::vector <long> bit_enc(nslots, (vb[i] >> j) & 0x01);
            ea.encrypt(snd_raw[i][j], public_key, bit_enc);
        }
    }

    std::vector <helib::CtPtrs_vectorCt> fst;
    std::vector <helib::CtPtrs_vectorCt> snd;

    for(int i = 0; i < va.size(); i++)
        fst.push_back(helib::CtPtrs_vectorCt(fst_raw[i]));

    for(int i = 0; i < vb.size(); i++)
        snd.push_back(helib::CtPtrs_vectorCt(snd_raw[i]));

    std::vector <helib::Ctxt> enc_lev_dist = lev_dist(fst, snd);
    helib::CtPtrs_vectorCt enc_lev_dist_wrap(enc_lev_dist);

    std::vector <long> dec_lev_dist;
    helib::decryptBinaryNums(dec_lev_dist, enc_lev_dist_wrap, secret_key, ea, false, true);

    std::cout << "BGV lev dist: " << dec_lev_dist[0] << "\n";
}

void test_sort(){

    const int V_LEN = 7;

    int v[V_LEN] = { 7, 10, 29, 2, 255, 49, 50 };

    // Plaintext prime modulus.
    long p = 2;
    // Cyclotomic polynomial - defines phi(m).
    long m = 4095;
    // Hensel lifting (default = 1).
    long r = 1;
    // Number of bits of the modulus chain.
    long bits = 500;
    // Number of columns of Key-Switching matrix (typically 2 or 3).
    long c = 2;
    // Factorisation of m required for bootstrapping.
    std::vector<long> mvec = {7, 5, 9, 13};
    // Generating set of Zm* group.
    std::vector<long> gens = {2341, 3277, 911};
    // Orders of the previous generators.
    std::vector<long> ords = {6, 4, 6};

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .thickboot()
                               .build();

    // Create a secret key associated with the context.
    helib::SecKey secret_key(context);
    // Generate the secret key.
    secret_key.GenSecKey();

    // Generate bootstrapping data.
    secret_key.genRecryptData();

    helib::addSome1DMatrices(secret_key);
    helib::addFrbMatrices(secret_key);

    // Public key management.
    // Set the secret key (upcast: SecKey is a subclass of PubKey).
    const helib::PubKey& public_key = secret_key;

    // Get the EncryptedArray of the context.
    const helib::EncryptedArray& ea = context.getEA();

    long nslots = ea.size();

    const int BITLEN = 8;

    helib::Ctxt empty_ctxt(public_key);
    std::vector <helib::Ctxt> empty(BITLEN, empty_ctxt);

    std::vector <std::vector <helib::Ctxt>> to_sort_raw(V_LEN, empty);

    for(int i = 0; i < V_LEN; i++){
        for(int j = 0; j < BITLEN; j++){

            std::vector <long> bit_enc(nslots, (v[i] >> j) & 0x01);
            ea.encrypt(to_sort_raw[i][j], public_key, bit_enc);
        }
    }

    std::vector <helib::CtPtrs_vectorCt> to_sort;

    for(int i = 0; i < V_LEN; i++)
        to_sort.push_back(helib::CtPtrs_vectorCt(to_sort_raw[i]));

    sort(to_sort, V_LEN);

    for(int i = 0; i < V_LEN; i++){

        std::vector <long> dec_sorted;
        helib::decryptBinaryNums(dec_sorted, to_sort[i], secret_key, ea, false, true);

        std::cout << dec_sorted[0] << " ";
    }
    std::cout << '\n';
}

void test_max_arr(){

    const int V_LEN = 7;

    int v[V_LEN] = { 7, 10, 29, 2, 255, 49, 50 };

    // Plaintext prime modulus.
    long p = 2;
    // Cyclotomic polynomial - defines phi(m).
    long m = 4095;
    // Hensel lifting (default = 1).
    long r = 1;
    // Number of bits of the modulus chain.
    long bits = 500;
    // Number of columns of Key-Switching matrix (typically 2 or 3).
    long c = 2;
    // Factorisation of m required for bootstrapping.
    std::vector<long> mvec = {7, 5, 9, 13};
    // Generating set of Zm* group.
    std::vector<long> gens = {2341, 3277, 911};
    // Orders of the previous generators.
    std::vector<long> ords = {6, 4, 6};

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .thickboot()
                               .build();

    // Create a secret key associated with the context.
    helib::SecKey secret_key(context);
    // Generate the secret key.
    secret_key.GenSecKey();

    // Generate bootstrapping data.
    secret_key.genRecryptData();

    helib::addSome1DMatrices(secret_key);
    helib::addFrbMatrices(secret_key);

    // Public key management.
    // Set the secret key (upcast: SecKey is a subclass of PubKey).
    const helib::PubKey& public_key = secret_key;

    // Get the EncryptedArray of the context.
    const helib::EncryptedArray& ea = context.getEA();

    long nslots = ea.size();

    const int BITLEN = 8;

    helib::Ctxt empty_ctxt(public_key);
    std::vector <helib::Ctxt> empty(BITLEN, empty_ctxt);

    std::vector <std::vector <helib::Ctxt>> values_raw(V_LEN, empty);

    for(int i = 0; i < V_LEN; i++){
        for(int j = 0; j < BITLEN; j++){

            std::vector <long> bit_enc(nslots, (v[i] >> j) & 0x01);
            ea.encrypt(values_raw[i][j], public_key, bit_enc);
        }
    }

    std::vector <helib::CtPtrs_vectorCt> values;

    for(int i = 0; i < V_LEN; i++)
        values.push_back(helib::CtPtrs_vectorCt(values_raw[i]));

    std::vector <helib::Ctxt> max_val = min(values);

    std::vector <long> dec_max;
    helib::decryptBinaryNums(dec_max, helib::CtPtrs_vectorCt(max_val), secret_key, ea, false, true);

    std::cout << dec_max[0] << '\n';
}

void test_shortest_path(){

    const int M_LEN = 4;
    int V_CNT = 4;

    std::vector <std::tuple <int, int, int>> ms_plain = {{3, 1, 8}, {0, 3, 3}, {3, 2, 6}, {2, 1, 10}};

    /*const int M_LEN = 2;
    int V_CNT = 3;

    std::vector <std::tuple <int, int, int>> ms_plain = {{2, 1, 15}, {0, 2, 3}};*/

    const int src = 0;
    const int dst = 1;

    // Plaintext prime modulus.
    long p = 2;
    // Cyclotomic polynomial - defines phi(m).
    long m = 4095;
    // Hensel lifting (default = 1).
    long r = 1;
    // Number of bits of the modulus chain.
    long bits = 500;
    // Number of columns of Key-Switching matrix (typically 2 or 3).
    long c = 2;
    // Factorisation of m required for bootstrapping.
    std::vector<long> mvec = {7, 5, 9, 13};
    // Generating set of Zm* group.
    std::vector<long> gens = {2341, 3277, 911};
    // Orders of the previous generators.
    std::vector<long> ords = {6, 4, 6};

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .thickboot()
                               .build();

    // Create a secret key associated with the context.
    helib::SecKey secret_key(context);
    // Generate the secret key.
    secret_key.GenSecKey();

    // Generate bootstrapping data.
    secret_key.genRecryptData();

    helib::addSome1DMatrices(secret_key);
    helib::addFrbMatrices(secret_key);

    // Public key management.
    // Set the secret key (upcast: SecKey is a subclass of PubKey).
    const helib::PubKey& public_key = secret_key;

    // Get the EncryptedArray of the context.
    const helib::EncryptedArray& ea = context.getEA();

    long nslots = ea.size();

    const int BITLEN = 8;

    helib::Ctxt empty_ctxt(public_key);
    std::vector <helib::Ctxt> empty(BITLEN, empty_ctxt);

    std::vector <std::tuple <int, int, helib::CtPtrs_vectorCt>> ms;

    std::vector <std::vector <helib::Ctxt>> weight_enc_raw(M_LEN, empty);

    for(int i = 0; i < M_LEN; i++){

        const long weight = std::get <2>(ms_plain[i]);
        for(int b = 0; b < BITLEN; b++){

            std::vector <long> bit_enc(nslots);

            for(int slot = 0; slot < nslots; slot++)
                bit_enc[slot] = (weight >> b) & 0x01;

            ea.encrypt(weight_enc_raw[i][b], public_key, bit_enc);
        }

        ms.push_back({std::get <0>(ms_plain[i]), std::get <1>(ms_plain[i]), helib::CtPtrs_vectorCt(weight_enc_raw[i])});
    }

    std::vector <helib::Ctxt> src_enc(empty);
    std::vector <helib::Ctxt> dst_enc(empty);

    for(int b = 0; b < BITLEN; b++){

        std::vector <long> bit_enc(nslots);

        for(int slot = 0; slot < nslots; slot++)
            bit_enc[slot] = (src >> b) & 0x01;
        
        ea.encrypt(src_enc[b], public_key, bit_enc);
    }

    for(int b = 0; b < BITLEN; b++){

        std::vector <long> bit_enc(nslots);

        for(int slot = 0; slot < nslots; slot++)
            bit_enc[slot] = (dst >> b) & 0x01;
        
        ea.encrypt(dst_enc[b], public_key, bit_enc);
    }

    std::vector <std::vector <helib::Ctxt>> dist = shortest_path_cost(ms, V_CNT, src_enc);

    for(int i = 0; i < V_CNT; i++){

        std::vector <long> dec_dist;
        helib::decryptBinaryNums(dec_dist, helib::CtPtrs_vectorCt(dist[i]), secret_key, ea, false, true);

        std::cout << dec_dist[0] << " ";
    }
    std::cout << '\n';
}

void t(){

    // Plaintext prime modulus.
    long p = 2;
    // Cyclotomic polynomial - defines phi(m).
    long m = 4095;
    // Hensel lifting (default = 1).
    long r = 1;
    // Number of bits of the modulus chain.
    long bits = 500;
    // Number of columns of Key-Switching matrix (typically 2 or 3).
    long c = 2;
    // Factorisation of m required for bootstrapping.
    std::vector<long> mvec = {7, 5, 9, 13};
    // Generating set of Zm* group.
    std::vector<long> gens = {2341, 3277, 911};
    // Orders of the previous generators.
    std::vector<long> ords = {6, 4, 6};

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .thickboot()
                               .build();

    // Create a secret key associated with the context.
    helib::SecKey secret_key(context);
    // Generate the secret key.
    secret_key.GenSecKey();

    // Generate bootstrapping data.
    secret_key.genRecryptData();

    helib::addSome1DMatrices(secret_key);
    helib::addFrbMatrices(secret_key);

    // Public key management.
    // Set the secret key (upcast: SecKey is a subclass of PubKey).
    const helib::PubKey& public_key = secret_key;

    // Get the EncryptedArray of the context.
    const helib::EncryptedArray& ea = context.getEA();

    long nslots = ea.size();
}

int main() {

    //test_eq_gt();

    //test_if_then_else();

    //test_lev_dist();

    //test_sort();

    //test_max_arr();

    //test_shortest_path();
  
    return 0;
}
