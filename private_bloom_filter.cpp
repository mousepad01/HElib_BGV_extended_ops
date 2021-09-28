#include "private_cmp.h"
#include "private_bloom_filter.h"

namespace heExtension {

    BloomFilter::BloomFilter(int hash_function_count, int bit_count, 
                            const helib::PubKey * pk, const helib::EncryptedArray * ea): hash_function_count(hash_function_count),
                                                                                            pk(pk), ea(ea) {

        const helib::Context & context = pk->getContext();

        if(context.isCKKS())
            throw new std::invalid_argument("The encryption scheme must be BGV (it appears to be CKKS)");
        
        if(context.getP() != 2)
            throw new std::invalid_argument("Plaintext modulus p != 2");

        this->N_SLOTS = ea->size();

        std::vector <long> aux_bits(N_SLOTS, 0);
        ea->encrypt(*CT_0, *pk, aux_bits);

        this->filter_length = bit_count / N_SLOTS;
        if(bit_count % N_SLOTS)
            this->filter_length += 1;

        this->filter = new std::vector <helib::Ctxt>(filter_length, *CT_0);

        aux_bits[N_SLOTS - 1] = 1;
        ea->encrypt(*QUERY_MASK, *pk, aux_bits);
    }

    BloomFilter::BloomFilter(int expected_element_count, double expected_false_positive_rate, int hash_function_count, 
                            const helib::PubKey * pk, const helib::EncryptedArray * ea): hash_function_count(hash_function_count), pk(pk), ea(ea) {
        
        const helib::Context & context = pk->getContext();

        if(context.isCKKS())
            throw new std::invalid_argument("The encryption scheme must be BGV (it appears to be CKKS)");
        
        if(context.getP() != 2)
            throw new std::invalid_argument("Plaintext modulus p != 2");

        int bit_count = ceil(expected_element_count * log(-expected_false_positive_rate) / (log(2) * log(2)));

        this->N_SLOTS = ea->size();

        std::vector <long> aux_bits(N_SLOTS, 0);
        ea->encrypt(*CT_0, *pk, aux_bits);

        this->filter_length = bit_count / N_SLOTS;
        if(bit_count % N_SLOTS)
            this->filter_length += 1;

        this->filter = new std::vector <helib::Ctxt>(filter_length, *CT_0);

        aux_bits[N_SLOTS - 1] = 1;
        ea->encrypt(*QUERY_MASK, *pk, aux_bits);
    }
    
    BloomFilter::~BloomFilter() {}

    void BloomFilter::add_element(const std::vector <helib::Ctxt> * to_add) {
        
        // A OR B = (A XOR B) XOR (A AND B)

        for(int i = 0; i < to_add->size(); i++) {

            this->filter->at(i) += to_add->at(i);

            helib::Ctxt aux = this->filter->at(i);
            aux *= to_add->at(i);

            this->filter->at(i) += aux;
        }
    }

    void BloomFilter::filter_union(const BloomFilter & other) {

        if(other.pk->getContext() != this->pk->getContext())
            throw std::invalid_argument("filter BGV contexts are different");

        this->add_element(other.filter);        
    }

    void BloomFilter::filter_intersection(const BloomFilter & other) {
    
        if(other.pk->getContext() != this->pk->getContext())
            throw std::invalid_argument("filter BGV contexts are different");

        for(int i = 0; i < other.filter->size(); i++) 
            this->filter->at(i) *= other.filter->at(i);
    }

    helib::Ctxt BloomFilter::__query_for_element(const std::vector <int> positions_to_query, const int pos_offset, const int pos_len) {

        if(pos_len == 1){

            int ctxt_i = positions_to_query[pos_offset] / this->N_SLOTS;
            int ctxt_offset = (this->N_SLOTS - 1) - (positions_to_query[pos_offset] % this->N_SLOTS);
            
            helib::Ctxt ctxt_cpy = this->filter->at(ctxt_i);
            this->ea->shift(ctxt_cpy, ctxt_offset);

            ctxt_cpy *= *this->QUERY_MASK;
            return ctxt_cpy;
        }
        else{

            helib::Ctxt fst_res = this->__query_for_element(positions_to_query, pos_offset, pos_len / 2);
            helib::Ctxt snd_res = this->__query_for_element(positions_to_query, pos_offset + pos_len / 2, pos_len - pos_len / 2);
        
            fst_res *= snd_res;
            return fst_res;
        }
    }

    helib::Ctxt BloomFilter::query_for_element(const std::vector <int> positions_to_query) {

        return this->__query_for_element(positions_to_query, 0, positions_to_query.size());
    }
}