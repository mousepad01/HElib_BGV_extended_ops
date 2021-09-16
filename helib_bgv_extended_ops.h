#include <vector>

#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

helib::Ctxt operator >(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

helib::Ctxt operator <(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

helib::Ctxt operator ==(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

helib::Ctxt operator !=(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

std::vector <helib::Ctxt> if_then_else(const helib::Ctxt & cond, const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd);

static inline std::vector <helib::Ctxt> max(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) { return if_then_else(fst > snd, fst, snd); }

static inline std::vector <helib::Ctxt> min(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) { return if_then_else(fst < snd, fst, snd); }

std::vector <helib::Ctxt> lev_dist(std::vector <helib::CtPtrs_vectorCt> & fst, std::vector <helib::CtPtrs_vectorCt> & snd, const int DIST_BITLEN = 8);

void sort(std::vector <helib::CtPtrs_vectorCt> & to_sort, int len, 
            std::function <helib::Ctxt(helib::CtPtrs_vectorCt, helib::CtPtrs_vectorCt)> comparator = operator >);