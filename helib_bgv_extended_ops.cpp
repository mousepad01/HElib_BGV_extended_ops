#include "helib_bgv_extended_ops.h"

static helib::Ctxt __eq(std::vector <helib::Ctxt> & fst, std::vector <helib::Ctxt> & snd,
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

static helib::Ctxt __gt(std::vector <helib::Ctxt> & fst, std::vector <helib::Ctxt> & snd,
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

helib::Ctxt operator >(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd) {

    int bitsize = fst.v.size();

    helib::Ctxt scratch(fst.v[0].getPubKey());

    std::vector <std::vector <std::pair <helib::Ctxt, bool>>> eq_dp(bitsize + 1, std::vector <std::pair <helib::Ctxt, bool>>(bitsize + 1, {scratch, false}));
    std::vector <std::vector <helib::Ctxt>> gt_dp(bitsize + 1, std::vector <helib::Ctxt>(bitsize + 1, scratch));

    return __gt(fst.v, snd.v, eq_dp, gt_dp, 0, bitsize);
}

helib::Ctxt operator <(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd) {

    int bitsize = fst.v.size();

    helib::Ctxt scratch(fst.v[0].getPubKey());

    std::vector <std::vector <std::pair <helib::Ctxt, bool>>> eq_dp(bitsize + 1, std::vector <std::pair <helib::Ctxt, bool>>(bitsize + 1, {scratch, false}));
    std::vector <std::vector <helib::Ctxt>> gt_dp(bitsize + 1, std::vector <helib::Ctxt>(bitsize + 1, scratch));

    return __gt(snd.v, fst.v, eq_dp, gt_dp, 0, bitsize);
}

helib::Ctxt operator ==(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd) {

    int bitsize = fst.v.size();
    helib::Ctxt scratch(fst.v[0].getPubKey());

    std::vector <std::vector <std::pair <helib::Ctxt, bool>>> eq_dp(bitsize + 1, std::vector <std::pair <helib::Ctxt, bool>>(bitsize + 1, {scratch, false}));

    return __eq(fst.v, snd.v, eq_dp, 0, bitsize);
}

helib::Ctxt operator !=(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd) {

    int bitsize = fst.v.size();
    helib::Ctxt scratch(fst.v[0].getPubKey());

    std::vector <std::vector <std::pair <helib::Ctxt, bool>>> eq_dp(bitsize + 1, std::vector <std::pair <helib::Ctxt, bool>>(bitsize + 1, {scratch, false}));

    helib::Ctxt eq_res = __eq(fst.v, snd.v, eq_dp, 0, bitsize);
    eq_res.addConstant(NTL::ZZX(1));

    return eq_res;
}

// cond ? fst : snd
std::vector <helib::Ctxt> if_then_else(const helib::Ctxt & cond, helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd) {

    std::vector <helib::Ctxt> result;

    std::vector <long> constant_1(fst.v[0].getContext().getEA().size(), 1);
    helib::Ptxt <helib::BGV> ptxt_constant_1(fst.v[0].getContext(), constant_1);

    helib::Ctxt neg_cond = cond;
    neg_cond.negate();
    neg_cond.addConstant(ptxt_constant_1);

    for(int i = 0; i < fst.v.size(); i++){

        result.push_back(fst.v[i]);
        result[i] *= cond;
        
        helib::Ctxt temp = neg_cond;
        temp *= snd.v[i];

        result[i] += temp;
    }
    
    return result;
}

