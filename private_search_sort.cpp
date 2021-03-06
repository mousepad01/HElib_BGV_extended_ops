#include "private_search_sort.h"

namespace heExtension{

    std::vector <helib::Ctxt> lev_dist(std::vector <helib::CtPtrs_vectorCt> & fst, std::vector <helib::CtPtrs_vectorCt> & snd, const int DIST_BITLEN) {

        int n = fst.size();
        int m = snd.size();

        const helib::PubKey & pk = fst[0].v[0].getPubKey();
        const helib::Context & context = fst[0].v[0].getContext();
        const helib::EncryptedArray & ea = context.getEA();

        helib::Ctxt empty_ctxt(pk);
        std::vector <helib::Ctxt> empty(DIST_BITLEN, empty_ctxt);

        std::vector <std::vector <helib::Ctxt>> d(m + 1, empty);
        std::vector <std::vector <helib::Ctxt>> d_prev(m + 1, empty);

        std::vector <helib::Ctxt> constant_1_aux = ct_bin_enc(1, DIST_BITLEN, ea, pk);
        helib::CtPtrs_vectorCt constant_1(constant_1_aux);

        std::vector<helib::zzX> unpackSlotEncoding;
        buildUnpackSlotEncoding(unpackSlotEncoding, ea);

        for(int j = 0; j <= m; j++){

            d_prev[j] = ct_bin_enc(j, DIST_BITLEN, ea, pk);
            d[j] = d_prev[j];
        }
        
        for(int i = 1; i <= n; i++){

            d[0] = ct_bin_enc(i, DIST_BITLEN, ea, pk);
            for(int j = 1; j <= m; j++){

                std::vector <helib::Ctxt> element_neq = to_ctxt_arr(fst[i - 1] != snd[j - 1], DIST_BITLEN, ea, pk);

                std::vector <helib::Ctxt> val0_aux(DIST_BITLEN, empty_ctxt);
                helib::CtPtrs_vectorCt val0(val0_aux);

                helib::addTwoNumbers(val0, helib::CtPtrs_vectorCt(element_neq), helib::CtPtrs_vectorCt(d_prev[j - 1]), DIST_BITLEN, &unpackSlotEncoding);

                std::vector <helib::Ctxt> val1_aux(DIST_BITLEN, empty_ctxt);
                helib::CtPtrs_vectorCt val1(val1_aux);  

                helib::addTwoNumbers(val1, helib::CtPtrs_vectorCt(d_prev[j]), constant_1, DIST_BITLEN, &unpackSlotEncoding);     
                
                std::vector <helib::Ctxt> val2_aux(DIST_BITLEN, empty_ctxt);
                helib::CtPtrs_vectorCt val2(val2_aux);

                helib::addTwoNumbers(val2, helib::CtPtrs_vectorCt(d[j - 1]), constant_1, DIST_BITLEN, &unpackSlotEncoding);

                if(val0.v[0].bitCapacity() < 200)
                    helib::packedRecrypt(val0, unpackSlotEncoding, ea);

                if(val1.v[0].bitCapacity() < 200)
                    helib::packedRecrypt(val1, unpackSlotEncoding, ea);

                if(val2.v[0].bitCapacity() < 200)
                    helib::packedRecrypt(val2, unpackSlotEncoding, ea);

                std::vector <helib::Ctxt> m1 = min(val0, val1);

                if(m1[0].bitCapacity() < 200)
                    helib::packedRecrypt(helib::CtPtrs_vectorCt(m1), unpackSlotEncoding, ea);

                d[j] = min(helib::CtPtrs_vectorCt(m1), val2);

                // empirical value
                if(d[j][0].bitCapacity() < 200)
                    helib::packedRecrypt(helib::CtPtrs_vectorCt(d[j]), unpackSlotEncoding, ea);
            
                d_prev[j - 1] = d[j - 1]; // prepare for the next value of i
            }
            d_prev[m] = d[m];
        }

        return d[m];
    }

    static std::vector <helib::Ctxt> __max(const std::vector <helib::CtPtrs_vectorCt> & values, int offset, int len) {

        if(len == 1)
            return values[offset].v;

        std::vector <helib::Ctxt> fst_max = __max(values, offset, len / 2);
        std::vector <helib::Ctxt> snd_max = __max(values, offset + len / 2, len - len / 2);

        return max(helib::CtPtrs_vectorCt(fst_max), helib::CtPtrs_vectorCt(snd_max));
    }

    static std::vector <helib::Ctxt> __min(const std::vector <helib::CtPtrs_vectorCt> & values, int offset, int len) {

        if(len == 1)
            return values[offset].v;

        std::vector <helib::Ctxt> fst_min = __min(values, offset, len / 2);
        std::vector <helib::Ctxt> snd_min = __min(values, offset + len / 2, len - len / 2);

        return min(helib::CtPtrs_vectorCt(fst_min), helib::CtPtrs_vectorCt(snd_min));
    }

    std::vector <helib::Ctxt> max(const std::vector <helib::CtPtrs_vectorCt> & values) {

        return __max(values, 0, values.size());
    }

    std::vector <helib::Ctxt> min(const std::vector <helib::CtPtrs_vectorCt> & values) {

        return __min(values, 0, values.size());
    }

    void sort(std::vector <helib::CtPtrs_vectorCt> & to_sort, int len, 
                std::function <helib::Ctxt(helib::CtPtrs_vectorCt, helib::CtPtrs_vectorCt)> comparator) {

        const helib::PubKey & pk = to_sort[0].v[0].getPubKey();
        const helib::Context & context = to_sort[0].v[0].getContext();
        const helib::EncryptedArray & ea = context.getEA();

        std::vector<helib::zzX> unpackSlotEncoding;
        buildUnpackSlotEncoding(unpackSlotEncoding, ea);

        for(int i = len - 1; i > 0; i--){
            for(int j = 0; j < i; j++){

                if(to_sort[j].v[0].bitCapacity() < 200)
                    helib::packedRecrypt(to_sort[j], unpackSlotEncoding, ea);

                if(to_sort[j + 1].v[0].bitCapacity() < 200)
                    helib::packedRecrypt(to_sort[j + 1], unpackSlotEncoding, ea);

                helib::Ctxt swap_condition = comparator(to_sort[j], to_sort[j + 1]);
                
                std::vector <helib::Ctxt> to_sort_j_v = if_then_else(swap_condition, to_sort[j + 1], to_sort[j]);
                std::vector <helib::Ctxt> to_sort_j1_v = if_then_else(swap_condition, to_sort[j], to_sort[j + 1]);

                to_sort[j].v = to_sort_j_v;
                to_sort[j + 1].v = to_sort_j1_v;
            }
        }
    }

    static std::vector <helib::Ctxt> __get_val_bykey(std::vector <std::vector <helib::Ctxt>> & keys, std::vector <helib::Ctxt> & searched_key,
                                                        std::vector <std::vector <helib::Ctxt>> & values, const int offset, const int len, 
                                                        std::vector <helib::zzX> & unpackSlotEncoding, const helib::PubKey & pk, const helib::EncryptedArray & ea) {
        
        const size_t BITLEN = values[0].size();

        if(len == 1) {

            std::vector <helib::Ctxt> CT_0_raw = ct_bin_enc(0, BITLEN, ea, pk);
            helib::CtPtrs_vectorCt CT_0_enc(CT_0_raw);
            helib::CtPtrs_vectorCt key_to_check(keys[offset]);
            helib::CtPtrs_vectorCt value_to_check(values[offset]);
            helib::CtPtrs_vectorCt searched_key_wrap(searched_key);

            return if_then_else(key_to_check == searched_key_wrap, value_to_check, CT_0_enc);
        }
        
        std::vector <helib::Ctxt> fst_res = __get_val_bykey(keys, searched_key, values, offset, len / 2, unpackSlotEncoding, pk, ea);
        std::vector <helib::Ctxt> snd_res = __get_val_bykey(keys, searched_key, values, offset + len / 2, len - len / 2, unpackSlotEncoding, pk, ea);

        std::vector <helib::Ctxt> res_raw;
        helib::CtPtrs_vectorCt res(res_raw);

        helib::addTwoNumbers(res, helib::CtPtrs_vectorCt(fst_res), helib::CtPtrs_vectorCt(snd_res), BITLEN, &unpackSlotEncoding);

        return res_raw;
    }

    std::vector <helib::Ctxt> shortest_path_cost(const std::vector <std::tuple <int, int, helib::CtPtrs_vectorCt>> & edges, const int node_cnt,
                                                    const helib::CtPtrs_vectorCt & src, const helib::CtPtrs_vectorCt & dst, const int DIST_BITLEN) {

        const helib::PubKey & pk = src.v[0].getPubKey();
        const helib::Context & context = src.v[0].getContext();
        const helib::EncryptedArray & ea = context.getEA();

        std::vector<helib::zzX> unpackSlotEncoding;
        buildUnpackSlotEncoding(unpackSlotEncoding, ea);

        helib::Ctxt empty_ctxt(pk);
        std::vector <helib::Ctxt> empty(DIST_BITLEN, empty_ctxt);

        /**
         * INF must be chosen so that it should be bigger than most values, but also
         * should not overflow, so that INF + (anything) ~= INF
         * 
         * max INF > sum(Wi + INF) =>
         * max INF > m * INF + sum(Wi)
         * assuming Wi = max(Wi) for every i,
         * max INF > m * INF + m * max(Wi) =>
         * max INF > m * (INF + max(Wi))
         * assuming max(Wi) = INF,
         * max INF > 2 * m * INF
         * the maximum possible value for max INF is (1 << DIST_BITLEN) - 1 => 
         * (1 << DIST_BITLEN) - 1 > 2 * m * INF =>
         * *** INF ~= ((1 << (DIST_BITLEN - 1)) / m) - 1 and max(Wi) < INF (i = 1, ... m) ***
        **/
        uint64_t INF = (((uint64_t)1 << (DIST_BITLEN - 1)) / edges.size()) - 1;
        std::vector <helib::Ctxt> inf_enc_aux = ct_bin_enc(INF, DIST_BITLEN, ea, pk);
        const helib::CtPtrs_vectorCt INF_enc = helib::CtPtrs_vectorCt(inf_enc_aux);

        std::vector <helib::Ctxt> CT_0_raw = ct_bin_enc(0, DIST_BITLEN, ea, pk);
        const helib::CtPtrs_vectorCt CT_0_enc = helib::CtPtrs_vectorCt(CT_0_raw);

        std::vector <std::vector <helib::Ctxt>> dist(node_cnt, empty);
        std::vector <std::vector <helib::Ctxt>> node_i_enc(node_cnt, empty);

        for(int node = 0; node < node_cnt; node++){

            node_i_enc[node] = ct_bin_enc(node, DIST_BITLEN, ea, pk);

            helib::Ctxt node_src_eq = helib::CtPtrs_vectorCt(node_i_enc[node]) == src;
            dist[node] = if_then_else(node_src_eq, CT_0_enc, INF_enc);
        }

        for(int rnd = 0; rnd < node_cnt - 1; rnd++){

            for(auto & n1_n2_cost : edges){

                int n1 = std::get <0>(n1_n2_cost);
                int n2 = std::get <1>(n1_n2_cost);
                helib::CtPtrs_vectorCt cost = std::get <2>(n1_n2_cost);

                std::vector <helib::Ctxt> new_cost_raw(DIST_BITLEN, empty_ctxt);
                helib::CtPtrs_vectorCt new_cost(new_cost_raw);

                if(dist[n1][0].bitCapacity() < 200)
                    helib::packedRecrypt(helib::CtPtrs_vectorCt(dist[n1]), unpackSlotEncoding, ea);

                if(dist[n2][0].bitCapacity() < 200)
                    helib::packedRecrypt(helib::CtPtrs_vectorCt(dist[n2]), unpackSlotEncoding, ea);

                helib::addTwoNumbers(new_cost, helib::CtPtrs_vectorCt(dist[n1]), cost, DIST_BITLEN, &unpackSlotEncoding);

                if(new_cost_raw[0].bitCapacity() < 200)
                    helib::packedRecrypt(new_cost, unpackSlotEncoding, ea);

                dist[n2] = min(new_cost, helib::CtPtrs_vectorCt(dist[n2]));

                if(dist[n2][0].bitCapacity() < 200)
                    helib::packedRecrypt(helib::CtPtrs_vectorCt(dist[n2]), unpackSlotEncoding, ea);
            }
        }

        return __get_val_bykey(node_i_enc, dst.v, dist, 0, node_cnt, unpackSlotEncoding, pk, ea);
    }

    std::vector <std::vector <helib::Ctxt>> shortest_path_cost(const std::vector <std::tuple <int, int, helib::CtPtrs_vectorCt>> & edges, const int node_cnt,
                                                                const helib::CtPtrs_vectorCt & src, const int DIST_BITLEN) {

        const helib::PubKey & pk = src.v[0].getPubKey();
        const helib::Context & context = src.v[0].getContext();
        const helib::EncryptedArray & ea = context.getEA();

        std::vector<helib::zzX> unpackSlotEncoding;
        buildUnpackSlotEncoding(unpackSlotEncoding, ea);

        helib::Ctxt empty_ctxt(pk);
        std::vector <helib::Ctxt> empty(DIST_BITLEN, empty_ctxt);

        /**
         * INF must be chosen so that it should be bigger than most values, but also
         * should not overflow, so that INF + (anything) ~= INF
         * 
         * max INF > sum(Wi + INF) =>
         * max INF > m * INF + sum(Wi)
         * assuming Wi = max(Wi) for every i,
         * max INF > m * INF + m * max(Wi) =>
         * max INF > m * (INF + max(Wi))
         * assuming max(Wi) = INF,
         * max INF > 2 * m * INF
         * the maximum possible value for max INF is (1 << DIST_BITLEN) - 1 => 
         * (1 << DIST_BITLEN) - 1 > 2 * m * INF =>
         * *** INF ~= ((1 << (DIST_BITLEN - 1)) / m) - 1 and max(Wi) < INF (i = 1, ... m) ***
        **/
        uint64_t INF = (((uint64_t)1 << (DIST_BITLEN - 1)) / edges.size()) - 1;
        std::vector <helib::Ctxt> inf_enc_aux = ct_bin_enc(INF, DIST_BITLEN, ea, pk);
        const helib::CtPtrs_vectorCt INF_enc = helib::CtPtrs_vectorCt(inf_enc_aux);

        std::vector <helib::Ctxt> CT_0_raw = ct_bin_enc(0, DIST_BITLEN, ea, pk);
        const helib::CtPtrs_vectorCt CT_0_enc = helib::CtPtrs_vectorCt(CT_0_raw);

        std::vector <std::vector <helib::Ctxt>> dist(node_cnt, empty);
        std::vector <std::vector <helib::Ctxt>> node_i_enc(node_cnt, empty);

        for(int node = 0; node < node_cnt; node++){

            node_i_enc[node] = ct_bin_enc(node, DIST_BITLEN, ea, pk);

            helib::Ctxt node_src_eq = helib::CtPtrs_vectorCt(node_i_enc[node]) == src;
            dist[node] = if_then_else(node_src_eq, CT_0_enc, INF_enc);
        }

        for(int rnd = 0; rnd < node_cnt - 1; rnd++){

            for(auto & n1_n2_cost : edges){

                int n1 = std::get <0>(n1_n2_cost);
                int n2 = std::get <1>(n1_n2_cost);
                helib::CtPtrs_vectorCt cost = std::get <2>(n1_n2_cost);

                std::vector <helib::Ctxt> new_cost_raw(DIST_BITLEN, empty_ctxt);
                helib::CtPtrs_vectorCt new_cost(new_cost_raw);

                if(dist[n1][0].bitCapacity() < 200)
                    helib::packedRecrypt(helib::CtPtrs_vectorCt(dist[n1]), unpackSlotEncoding, ea);

                if(dist[n2][0].bitCapacity() < 200)
                    helib::packedRecrypt(helib::CtPtrs_vectorCt(dist[n2]), unpackSlotEncoding, ea);

                helib::addTwoNumbers(new_cost, helib::CtPtrs_vectorCt(dist[n1]), cost, DIST_BITLEN, &unpackSlotEncoding);

                if(new_cost_raw[0].bitCapacity() < 200)
                    helib::packedRecrypt(new_cost, unpackSlotEncoding, ea);

                dist[n2] = min(new_cost, helib::CtPtrs_vectorCt(dist[n2]));

                if(dist[n2][0].bitCapacity() < 200)
                    helib::packedRecrypt(helib::CtPtrs_vectorCt(dist[n2]), unpackSlotEncoding, ea);
            }
        }

        return dist;
    }
}

