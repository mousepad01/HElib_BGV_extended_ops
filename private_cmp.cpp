#include "private_cmp.h"

namespace heExtension{

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

}