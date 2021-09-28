#include "private_cmp.h"
#include "private_bloom_filter.h"

namespace heExtension {

    BloomFilter::BloomFilter(int hash_function_count, int bit_count, 
                            const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context): 
                            hash_function_count(hash_function_count), pk(pk), ea(ea), context(context), hash_functions(nullptr) {

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

    BloomFilter::BloomFilter(int expected_element_count, double expected_false_positive_rate, int hash_function_count, 
                            const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context): 
                            hash_function_count(hash_function_count), pk(pk), ea(ea), context(context), hash_functions(nullptr) {

        if(context.isCKKS())
            throw new std::invalid_argument("The encryption scheme must be BGV (it appears to be CKKS)");
        
        if(context.getP() != 2)
            throw new std::invalid_argument("Plaintext modulus p != 2");

        int bit_count = ceil(expected_element_count * log(-expected_false_positive_rate) / (log(2) * log(2)));

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
    
    BloomFilter::BloomFilter(int hash_function_count, int bit_count, 
                            const helib::PubKey & pk, const helib::EncryptedArray & ea, const helib::Context & context,
                            std::vector <std::function <std::vector <int>(const void *, size_t len)>> * hash_functions):
                            hash_function_count(hash_function_count), pk(pk), ea(ea), context(context), 
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

        for(int i = 0; i < to_add->size(); i++) {

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

        for(int i = 0; i < other.filter->size(); i++) 
            this->filter->at(i) *= other.filter->at(i);
    }

    helib::Ctxt BloomFilter::__query_for_element(std::vector <int> positions_to_query, const int pos_offset, const int pos_len) const {

        if(pos_len == 1){

            int ctxt_i = positions_to_query[pos_offset] / this->N_SLOTS;
            int ctxt_offset = (this->N_SLOTS - 1) - (positions_to_query[pos_offset] % this->N_SLOTS);
            
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

    helib::Ctxt BloomFilter::query_for_element(std::vector <int> positions_to_query) const {

        if(this->filter == nullptr)
            throw std::runtime_error("filter elements uninitialized");

        std::sort(positions_to_query.begin(), positions_to_query.end());

        return this->__query_for_element(positions_to_query, 0, positions_to_query.size());
    }

    std::vector <int> BloomFilter::create_query(const void * element, size_t len) {
        
        if(this->hash_functions == nullptr)
            throw std::runtime_error("hash functions uninitialized");

        if(this->hash_functions->size() != this->hash_function_count)
            throw std::runtime_error("not enough hash functions");

        std::vector <int> query_positions;
        
        for(int i = 0; i < this->hash_function_count; i++){

            std::vector <int> h_query_pos = this->hash_functions->at(i)(element, len);

            for(int j = 0; j < h_query_pos.size(); j++)
                h_query_pos.push_back(h_query_pos[j]);
        }

        return query_positions;
    }

    std::vector <helib::Ctxt> BloomFilter::create_add_mask(const void * element, size_t len) {
        
        if(this->hash_functions == nullptr)
            throw std::runtime_error("hash functions uninitialized");

        if(this->hash_functions->size() != this->hash_function_count)
            throw std::runtime_error("not enough hash functions");

        std::vector <helib::Ctxt> add_req_mask(filter_length, *CT_0);

         for(int i = 0; i < this->hash_function_count; i++){

            std::vector <int> h_query_pos = this->hash_functions->at(i)(element, len);

            //TODO divide et impera for add request mask generator
        }

        return add_req_mask;
    }

    bool BloomFilter::parse_query_response(const helib::Ctxt & res, const helib::SecKey & sk) {
        
        helib::Ptxt<helib::BGV> res_ptxt(this->context);
        sk.Decrypt(res_ptxt, res);

        long res_final = static_cast <long>(res_ptxt[this->N_SLOTS - 1]);

        return (res_final ? true : false);
    }
}