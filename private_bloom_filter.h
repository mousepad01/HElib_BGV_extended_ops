#ifndef PRIVATE_BLOOM_FILTER_H
#define PRIVATE_BLOOM_FILTER_H

#include "utils.h"

namespace heExtension {

    class BloomFilterClient;

    /**
     * Bloom filter with HElib-BGV encrypted bytes
     * It makes use of SIMD packing to store multiple bits in a single ciphertext, shifting slots when necessary
     * It provides both server-side (the bloom filter itself) and client-side (querying) support in the same class
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

        /**
         * Per-object constants stored here to avoid multiple initializations
        **/

        /**
         * 0 on every slot
        **/
        helib::Ctxt * CT_0;

        /**
         * 1 on the last slot (from left to right)
        **/
        helib::Ctxt * QUERY_MASK;

        /**
         * number of slots in a BGV plaintext
        **/
        long N_SLOTS;

        /**
         * information for diverse BGV operations
        **/
        const helib::EncryptedArray & ea;

        /**
         * BGV public key
        **/
        const helib::PubKey & pk;

        /**
         * BGV context
        **/
        const helib::Context & context;

        /**
         * Auxiliary method for implementing divide-et-impera query exeuction
        **/
        helib::Ctxt __query_for_element(const std::vector <int> positions_to_query, const int pos_offset, const int pos_len) const;

        /**
         * TODO Auxiliary method for implementing divide-et-impera add mask creation
        **/
        helib::Ctxt __create_add_mask() const;

    public:

        int hash_function_count;
        int filter_length;

        /**
         * Used server-side 
        **/
        std::vector <helib::Ctxt> * filter;

        /**
         * Used (mostly) client-side
        **/
        std::vector <std::function <int(const void *, size_t len)>> * hash_functions;

        /**
         * SERVER-SIDE Constructor with custom parameters
        **/
        BloomFilter(int hash_function_count, int bit_count, 
                    const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context);

        /**
         * SERVER-SIDE Constructor with automatic size selection
        **/
        BloomFilter(int expected_element_count, double expected_false_positive_rate, int hash_function_count, 
                    const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context);
        
        /**
         * CLIENT-SIDE Constructor with manual hashing function selection
        **/
        BloomFilter(int hash_function_count, int bit_count, 
                    const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context,
                    std::vector <std::function <int(const void *, size_t len)>> * hash_functions);

        /**
         * Destructor
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
        void add_element(const std::vector <helib::Ctxt> * to_add);

        /**
         * Union of two filters
         * Time complexity (excluding HE operation overhead): O(filter length)
        **/
        void filter_union(const BloomFilter & other);

        /**
         * Intersection of two filters
         * TIme complexity (excluding HE operation overhead): O(filter length)
        **/
        void filter_intersection(const BloomFilter & other);

        /**
         * Query for an element in the filter
         * The input is a vector of positions to be considered when querying
         * Time complexity (excluding HE operation overhead): O(number of positions to query)
        **/
        helib::Ctxt query_for_element(std::vector <int> positions_to_query) const;

        /**
         * Create a query argument
        **/
        std::vector <int> create_query(const void * element, size_t len);

        /**
         * TODO Create an add request argument
        **/
        std::vector <helib::Ctxt> create_add_mask(const void * element, size_t len);

        /**
         * Decrypt (and decode) the query result
        **/
        bool parse_query_response(const helib::Ctxt & res, const helib::SecKey & sk);
    };
}

#endif