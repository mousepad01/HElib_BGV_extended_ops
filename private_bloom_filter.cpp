#include "private_bloom_filter.h"

namespace heExtension {

    BloomFilter::BloomFilter(int hash_function_count, int filter_length, 
                            helib::PubKey * pk, helib::EncryptedArray * ea): hash_function_count(hash_function_count), filter_length(filter_length),
                                                                                pk(pk), ea(ea) {
        }

    BloomFilter::BloomFilter(int expected_element_count, double expected_false_positive_rate, int hash_function_count, 
                                helib::PubKey * pk, helib::EncryptedArray * ea): hash_function_count(hash_function_count), pk(pk), ea(ea) {

        this->filter_length = ceil(expected_element_count * log(-expected_false_positive_rate) / (log(2) * log(2)));

        
    }
    
    BloomFilter::~BloomFilter() {}

    void BloomFilter::add_element(const std::vector <helib::Ctxt> to_add) {}

    void BloomFilter::filter_union(const BloomFilter & other) {}

    //helib::Ctxt query_for_element(const std::vector <int> positions_to_query);
}