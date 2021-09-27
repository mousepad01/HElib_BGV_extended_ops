#ifndef PRIVATE_CMP_H
#define PRIVATE_CMP_H

#include "utils.h"

namespace heExtension{

    helib::Ctxt operator >(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

    helib::Ctxt operator <(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

    helib::Ctxt operator ==(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

    helib::Ctxt operator !=(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

    /**
     * if(cond) { return fst; }
     * else { return snd; }
    **/
    std::vector <helib::Ctxt> if_then_else(const helib::Ctxt & cond, const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);
}

#endif