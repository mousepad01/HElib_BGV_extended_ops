#ifndef PRIVATE_BLOOM_FILTER_H
#define PRIVATE_BLOOM_FILTER_H

#include "utils.h"

namespace heExtension {

    /**
     * Bloom filter with HElib-BGV encrypted bytes
     * It makes use of SIMD packing to store multiple bits in a single ciphertext, rotating slots when necessary
     * 
     * 
     * Advantages over a classic, "plaintext" bloom filter:
     * * The processing party does not learn the hash of a freshly added element
     * * The processing party does not learn the result of the queries (considering careful usage)
     * 
     * It can be paired with keyed hashing functions, which will prevent anybody from executing arbitrary queries on the filter
     * 
     * Unsolved (potential) privacy disadvantages:
     * * The processing party CAN LEARN QUERY PATTERNS
     * * The processing party can still DEDUCE QUERY RESULTS, if the bloom filter search is followed by a naive database search request
     * 
     * DOCUMENTATION SOURCES: 
     * * considering the usage of keyed hashing functions, the implementation was inspired by https://www.ncbi.nlm.nih.gov/pmc/articles/PMC5547447/
     * * automatic parameter selection was implemented according to https://arxiv.org/pdf/1903.12525.pdf, section 2
    **/
    class BloomFilter {

        helib::Ctxt CT_0;
        helib::Ctxt QUERY_MASK;

    public:

        int hash_function_count;
        int filter_length;

        std::vector <helib::Ctxt> filter;

        helib::PubKey * pk;
        helib::EncryptedArray * ea;

        /**
         * Constructor with custom parameters
        **/
        BloomFilter(int hash_function_count, int filter_length, helib::PubKey * pk, helib::EncryptedArray * ea);

        /**
         * Constructor with automatic size selection
        **/
        BloomFilter(int expected_element_count, double expected_false_positive_rate, int hash_function_count, helib::PubKey * pk, helib::EncryptedArray * ea);

        /**
         * Trivial destructor
        **/
        ~BloomFilter();

        BloomFilter(const BloomFilter & other) = delete;
        BloomFilter(BloomFilter && other) = delete;

        BloomFilter operator =(const BloomFilter & other) = delete;
        BloomFilter operator =(BloomFilter && other) = delete;

        /**
         * Add an element to the filter
         * The element should be in the form of a new bloom filter that contains only the element that needs to be added
         * (Equivalent to union with a filter containing only that element)
         * Time complexity (excluding HE operation overhead): O(filter length) 
        **/
        void add_element(const std::vector <helib::Ctxt> to_add);

        /**
         * Union of two filters
         * TIme complexity (excluding HE operation overhead): O(filter length)
        **/
        void filter_union(const BloomFilter & other);

        /**
         * Query for an element in the filter
         * The input is a vector of positions to be considered when querying
         * Time complexity (excluding HE operation overhead): O(number of positions to query)
        **/
        helib::Ctxt query_for_element(const std::vector <int> positions_to_query);
    };
}

#endif