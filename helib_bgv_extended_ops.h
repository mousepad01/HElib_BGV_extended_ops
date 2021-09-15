#include <vector>

#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

helib::Ctxt operator >(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd);

helib::Ctxt operator <(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd);

helib::Ctxt operator ==(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd);

helib::Ctxt operator !=(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd);

std::vector <helib::Ctxt> if_then_else(const helib::Ctxt & cond, helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd);

static inline std::vector <helib::Ctxt> max(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd) { return if_then_else(fst > snd, fst, snd); }

static inline std::vector <helib::Ctxt> min(helib::CtPtrs_vectorCt & fst, helib::CtPtrs_vectorCt & snd) { return if_then_else(fst < snd, fst, snd); }