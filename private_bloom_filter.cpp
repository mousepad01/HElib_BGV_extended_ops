#include "private_cmp.h"
#include "private_bloom_filter.h"

namespace heExtension {

    BloomFilter::BloomFilter(int hash_function_count, int bit_count, 
                            helib::PubKey * pk, helib::EncryptedArray * ea): hash_function_count(hash_function_count),
                                                                                pk(pk), ea(ea) {

        helib::Context context = pk->getContext();

        if(context.isCKKS())
            throw new std::invalid_argument("The encryption scheme must be BGV (it appears to be CKKS)");
        
        if(context.getP() != 2)
            throw new std::invalid_argument("Plaintext modulus p != 2");

        long nslots = ea.size();

        std::vector <long> aux_bits(nslots, 0);
        ea.encrypt(this->CT_0, *pk, aux_bits);

        this->filter_length = bit_count / nslots;
        if(bit_count % nslots)
            this->filter_length += 1;

        this->filter = std::vector <helib::Ctxt>(filter_length, this->CT_0);

        aux_bits[0] = 1;
        ea.encrypt(this->QUERY_MASK, *pk, aux_bits);
    }

    BloomFilter::BloomFilter(int expected_element_count, double expected_false_positive_rate, int hash_function_count, 
                                helib::PubKey * pk, helib::EncryptedArray * ea): hash_function_count(hash_function_count), pk(pk), ea(ea) {
        
        helib::Context context = pk->getContext();

        if(context.isCKKS())
            throw new std::invalid_argument("The encryption scheme must be BGV (it appears to be CKKS)");
        
        if(context.getP() != 2)
            throw new std::invalid_argument("Plaintext modulus p != 2");

        int bit_count = ceil(expected_element_count * log(-expected_false_positive_rate) / (log(2) * log(2)));

        long nslots = ea.size();

        std::vector <long> aux_bits(nslots, 0);
        ea.encrypt(this->CT_0, *pk, aux_bits);

        this->filter_length = bit_count / nslots;
        if(bit_count % nslots)
            this->filter_length += 1;

        this->filter = std::vector <helib::Ctxt>(filter_length, this->CT_0);

        aux_bits[0] = 1;
        ea.encrypt(this->QUERY_MASK, *pk, aux_bits);
    }
    
    BloomFilter::~BloomFilter() {}

    void BloomFilter::add_element(const std::vector <helib::Ctxt> to_add) {
        
        // A OR B = (A XOR B) XOR (A AND B)

        for(int i = 0; i < to_add.size(); i++){

            this->filter[i] += to_add[i];
            this->filter[i] += (this->filter[i] * to_add[i]);
        }
    }

    void BloomFilter::filter_union(const BloomFilter & other) {

        if(other.getContext() != this->pk->getContext())
            throw std::invalid_argument("filter BGV context are different");

        this->add_element(other.filter);        
    }

    //helib::Ctxt query_for_element(const std::vector <int> positions_to_query);
}