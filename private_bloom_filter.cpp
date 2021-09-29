#include "private_cmp.h"
#include "private_bloom_filter.h"

namespace heExtension {

    BloomFilter::BloomFilter(uint32_t hash_function_count, uint32_t bit_count, 
                            const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context): 
                            hash_function_count(hash_function_count), filter_bit_length(bit_count),
                            pk(pk), ea(ea), context(context), hash_functions(nullptr) {

        if(context.isCKKS())
            throw new std::invalid_argument("The encryption scheme must be BGV (it appears to be CKKS)");
        
        if(context.getP() != 2)
            throw new std::invalid_argument("Plaintext modulus p != 2");

        this->N_SLOTS = ea.size();

        this->CT_0 = new helib::Ctxt(pk);
        this->QUERY_MASK = new helib::Ctxt(pk);

        std::vector <long> aux_bits(N_SLOTS, 0);
        ea.encrypt(*CT_0, pk, aux_bits);

        this->filter_length = bit_count / N_SLOTS;
        if(bit_count % N_SLOTS)
            this->filter_length += 1;

        this->filter = new std::vector <helib::Ctxt>(filter_length, *CT_0);

        aux_bits[N_SLOTS - 1] = 1;
        ea.encrypt(*QUERY_MASK, pk, aux_bits);
    }

    BloomFilter::BloomFilter(uint32_t expected_element_count, double expected_false_positive_rate, uint32_t hash_function_count, 
                            const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context): 
                            hash_function_count(hash_function_count), pk(pk), ea(ea), context(context), hash_functions(nullptr) {

        if(context.isCKKS())
            throw new std::invalid_argument("The encryption scheme must be BGV (it appears to be CKKS)");
        
        if(context.getP() != 2)
            throw new std::invalid_argument("Plaintext modulus p != 2");

        this->filter_bit_length = ceil(expected_element_count * log(-expected_false_positive_rate) / (log(2) * log(2)));

        this->N_SLOTS = ea.size();

        this->CT_0 = new helib::Ctxt(pk);
        this->QUERY_MASK = new helib::Ctxt(pk);

        std::vector <long> aux_bits(N_SLOTS, 0);
        ea.encrypt(*CT_0, pk, aux_bits);

        this->filter_length = filter_bit_length / N_SLOTS;
        if(filter_bit_length % N_SLOTS)
            this->filter_length += 1;

        this->filter = new std::vector <helib::Ctxt>(filter_length, *CT_0);

        aux_bits[N_SLOTS - 1] = 1;
        ea.encrypt(*QUERY_MASK, pk, aux_bits);
    }
    
    BloomFilter::BloomFilter(uint32_t hash_function_count, uint32_t bit_count, 
                            const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context,
                            std::vector <std::function <uint32_t(const void *, size_t len)>> * hash_functions):
                            hash_function_count(hash_function_count), filter_bit_length(bit_count),
                            pk(pk), ea(ea), context(context), 
                            hash_functions(hash_functions), filter(nullptr) {
        
        if(context.isCKKS())
            throw new std::invalid_argument("The encryption scheme must be BGV (it appears to be CKKS)");
        
        if(context.getP() != 2)
            throw new std::invalid_argument("Plaintext modulus p != 2");

        this->N_SLOTS = ea.size();

        this->CT_0 = new helib::Ctxt(pk);
        this->QUERY_MASK = new helib::Ctxt(pk);

        std::vector <long> aux_bits(N_SLOTS, 0);
        ea.encrypt(*CT_0, pk, aux_bits);

        this->filter_length = bit_count / N_SLOTS;
        if(bit_count % N_SLOTS)
            this->filter_length += 1;

        aux_bits[N_SLOTS - 1] = 1;
        ea.encrypt(*QUERY_MASK, pk, aux_bits);
    }

    BloomFilter::~BloomFilter() {

        delete this->CT_0;
        delete this->QUERY_MASK;
        
        if(this->filter != nullptr)
            delete this->filter;

        if(this->hash_functions != nullptr)
            delete this->hash_functions;
    }

    void BloomFilter::add_element(const std::vector <helib::Ctxt> * to_add) {

        if(this->filter == nullptr)
            throw std::runtime_error("filter elements uninitialized");
    
        if(to_add->at(0).getContext() != this->context)
            throw std::invalid_argument("BGV contexts are different");
        
        // A OR B = (A XOR B) XOR (A AND B)

        for(uint32_t i = 0; i < to_add->size(); i++) {

            this->filter->at(i) += to_add->at(i);

            helib::Ctxt aux = this->filter->at(i);
            aux *= to_add->at(i);

            this->filter->at(i) += aux;
        }
    }

    void BloomFilter::filter_union(const BloomFilter & other) {

        if(this->filter == nullptr)
            throw std::runtime_error("filter elements uninitialized");

        if(other.context != this->context)
            throw std::invalid_argument("filter BGV contexts are different");

        this->add_element(other.filter);        
    }

    void BloomFilter::filter_intersection(const BloomFilter & other) {

        if(this->filter == nullptr)
            throw std::runtime_error("filter elements uninitialized");
    
        if(other.context != this->context)
            throw std::invalid_argument("filter BGV contexts are different");

        for(uint32_t i = 0; i < other.filter->size(); i++) 
            this->filter->at(i) *= other.filter->at(i);
    }

    helib::Ctxt BloomFilter::__query_for_element(std::vector <uint32_t> positions_to_query, const uint32_t pos_offset, const uint32_t pos_len) const {

        if(pos_len == 1){

            uint32_t ctxt_i = positions_to_query[pos_offset] / this->N_SLOTS;
            uint32_t ctxt_offset = (this->N_SLOTS - 1) - (positions_to_query[pos_offset] % this->N_SLOTS);
            
            helib::Ctxt ctxt_cpy = this->filter->at(ctxt_i);
            this->ea.shift(ctxt_cpy, ctxt_offset);

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

    helib::Ctxt BloomFilter::query_for_element(std::vector <uint32_t> positions_to_query) const {

        if(this->filter == nullptr)
            throw std::runtime_error("filter elements uninitialized");

        std::sort(positions_to_query.begin(), positions_to_query.end());

        return this->__query_for_element(positions_to_query, 0, positions_to_query.size());
    }

    std::vector <uint32_t> BloomFilter::create_query(const void * element, size_t len) {
        
        if(this->hash_functions == nullptr)
            throw std::runtime_error("hash functions uninitialized");

        if(this->hash_functions->size() != this->hash_function_count)
            throw std::runtime_error("not enough hash functions");

        std::vector <uint32_t> query_positions;
        
        for(uint32_t i = 0; i < this->hash_function_count; i++)
            query_positions.push_back(this->hash_functions->at(i)(element, len) % this->filter_bit_length);

        return query_positions;
    }

    std::vector <helib::Ctxt> BloomFilter::create_add_mask(const void * element, size_t len) {
        
        if(this->hash_functions == nullptr)
            throw std::runtime_error("hash functions uninitialized");

        if(this->hash_functions->size() != this->hash_function_count)
            throw std::runtime_error("not enough hash functions");

        std::vector <helib::Ctxt> ctxt_add_mask(filter_length, *CT_0);

        std::vector <std::vector <long>> ptxt_add_mask(this->filter_length, std::vector <long>(this->N_SLOTS, 0));
        std::vector <bool> only_0s(true, this->filter_length);

        for(uint32_t i = 0; i < this->hash_function_count; i++){

            uint32_t pos = this->hash_functions->at(i)(element, len);
            pos %= this->filter_bit_length;
            
            uint32_t mask_i = pos / this->N_SLOTS;
            uint32_t mask_offset = (this->N_SLOTS - 1) - (pos % this->N_SLOTS);

            ptxt_add_mask[mask_i][mask_offset] = 1;
            only_0s[mask_i] = false;
        }

        for(uint32_t i = 0; i < this->filter_length; i++)
            if(!only_0s[i])
                this->ea.encrypt(ctxt_add_mask[i], this->pk, ptxt_add_mask[i]);

        return ctxt_add_mask;
    }

    bool BloomFilter::parse_query_response(const helib::Ctxt & res, const helib::SecKey & sk) {
        
        helib::Ptxt<helib::BGV> res_ptxt(this->context);
        sk.Decrypt(res_ptxt, res);

        long res_final = static_cast <long>(res_ptxt[this->N_SLOTS - 1]);

        return (res_final ? true : false);
    }

}