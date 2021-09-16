#include "helib_bgv_extended_ops.h"

static helib::Ctxt __eq(const std::vector <helib::Ctxt> & fst, const std::vector <helib::Ctxt> & snd,
                        std::vector <std::vector <std::pair <helib::Ctxt, bool>>> & eq_dp, 
                        int i, int j) {

    if(eq_dp[i][j].second)
        return eq_dp[i][j].first;

    if(j == 1){

        eq_dp[i][1].first = fst[i];
        eq_dp[i][1].first += snd[i];
        eq_dp[i][1].first.addConstant(NTL::ZZX(1));
    }
    else{

        eq_dp[i][j].first = __eq(fst, snd, eq_dp, i, j / 2);
        eq_dp[i][j].first *= __eq(fst, snd, eq_dp, i + j / 2, j - j / 2);
    }
    
    eq_dp[i][j].second = true;

    return eq_dp[i][j].first;
}

static helib::Ctxt __gt(const std::vector <helib::Ctxt> & fst, const std::vector <helib::Ctxt> & snd,
                        std::vector <std::vector <std::pair <helib::Ctxt, bool>>> & eq_dp, 
                        std::vector <std::vector <helib::Ctxt>> & gt_dp, 
                        int i, int j) {

    if(j == 1){

        gt_dp[i][1] = fst[i];
        gt_dp[i][1] *= snd[i];
        gt_dp[i][1] += fst[i];
    }
    else{

        gt_dp[i][j] = __gt(fst, snd, eq_dp, gt_dp, i + j / 2, j - j / 2);

        helib::Ctxt gt_lsb = __eq(fst, snd, eq_dp, i + j / 2, j - j / 2);
        gt_lsb *= __gt(fst, snd, eq_dp, gt_dp, i, j / 2);

        gt_dp[i][j] += gt_lsb;
    }

    return gt_dp[i][j];
}

helib::Ctxt operator >(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) {

    int bitsize = fst.v.size();

    helib::Ctxt scratch(fst.v[0].getPubKey());

    std::vector <std::vector <std::pair <helib::Ctxt, bool>>> eq_dp(bitsize + 1, std::vector <std::pair <helib::Ctxt, bool>>(bitsize + 1, {scratch, false}));
    std::vector <std::vector <helib::Ctxt>> gt_dp(bitsize + 1, std::vector <helib::Ctxt>(bitsize + 1, scratch));

    return __gt(fst.v, snd.v, eq_dp, gt_dp, 0, bitsize);
}

helib::Ctxt operator <(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) {

    int bitsize = fst.v.size();

    helib::Ctxt scratch(fst.v[0].getPubKey());

    std::vector <std::vector <std::pair <helib::Ctxt, bool>>> eq_dp(bitsize + 1, std::vector <std::pair <helib::Ctxt, bool>>(bitsize + 1, {scratch, false}));
    std::vector <std::vector <helib::Ctxt>> gt_dp(bitsize + 1, std::vector <helib::Ctxt>(bitsize + 1, scratch));

    return __gt(snd.v, fst.v, eq_dp, gt_dp, 0, bitsize);
}

helib::Ctxt operator ==(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) {

    int bitsize = fst.v.size();
    helib::Ctxt scratch(fst.v[0].getPubKey());

    std::vector <std::vector <std::pair <helib::Ctxt, bool>>> eq_dp(bitsize + 1, std::vector <std::pair <helib::Ctxt, bool>>(bitsize + 1, {scratch, false}));

    return __eq(fst.v, snd.v, eq_dp, 0, bitsize);
}

helib::Ctxt operator !=(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) {

    int bitsize = fst.v.size();
    helib::Ctxt scratch(fst.v[0].getPubKey());

    std::vector <std::vector <std::pair <helib::Ctxt, bool>>> eq_dp(bitsize + 1, std::vector <std::pair <helib::Ctxt, bool>>(bitsize + 1, {scratch, false}));

    helib::Ctxt eq_res = __eq(fst.v, snd.v, eq_dp, 0, bitsize);
    eq_res.addConstant(NTL::ZZX(1));

    return eq_res;
}

// cond ? fst : snd
std::vector <helib::Ctxt> if_then_else(const helib::Ctxt & cond, const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) {

    std::vector <helib::Ctxt> result;

    helib::Ctxt neg_cond = cond;
    neg_cond.addConstant(NTL::ZZX(1));

    for(int i = 0; i < fst.v.size(); i++){

        result.push_back(fst.v[i]);
        result[i] *= cond;
        
        helib::Ctxt temp = neg_cond;
        temp *= snd.v[i];

        result[i] += temp;
    }

    return result;
}

static std::vector <helib::Ctxt> ct_bin_enc(long to_encode, int bitlen, const helib::EncryptedArray & ea, const helib::PubKey & pk) {

    helib::Ctxt empty(pk);
    std::vector <helib::Ctxt> ct_enc(bitlen, empty);

    int nslots = ea.size();

    for(int b = 0; b < bitlen; b++){

        std::vector <long> bit_enc(nslots);

        for(int slot = 0; slot < nslots; slot++)
            bit_enc[slot] = (to_encode >> b) & 0x01;

        ea.encrypt(ct_enc[b], pk, bit_enc);
    }

    return ct_enc;
}

static inline std::vector <helib::Ctxt> to_ctxt_arr(const helib::Ctxt & bit_to_encapsulate, int bitlen, const helib::EncryptedArray & ea, const helib::PubKey & pk) {

    std::vector <helib::Ctxt> converted = ct_bin_enc(0, bitlen, ea, pk);
    converted[0] = bit_to_encapsulate;

    return converted;
}

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