#ifndef PRIVATE_SEARCH_SORT_H
#define PRIVATE_SEARCH_SORT_H

#include "utils.h"
#include "private_cmp.h"

namespace heExtension{

    /**
     * Maximum between two values
     * NOTE: for maximum over a vector, use the overloaded function instead of manually iterating and calling this function
    **/
    static inline std::vector <helib::Ctxt> max(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) { return if_then_else(fst > snd, fst, snd); }

    /**
     * Minimum between two values
     * NOTE: for minimum over a vector, use the overloaded function instead of manually iterating and calling this function
    **/
    static inline std::vector <helib::Ctxt> min(const helib::CtPtrs_vectorCt & fst, const helib::CtPtrs_vectorCt & snd) { return if_then_else(fst < snd, fst, snd); }

    /**
     * Compute the levenshtein distance between two encrypted strings
     * The algorithm is implemented as the optimised DP that has O(n*m) time complexity and O(m) space complexity
    **/
    std::vector <helib::Ctxt> lev_dist(std::vector <helib::CtPtrs_vectorCt> & fst, std::vector <helib::CtPtrs_vectorCt> & snd, const int DIST_BITLEN = 8);

    /**
     * Find the maximum value from an array, in a divide-et-impera manner to decrease operation circuit depth
    **/
    std::vector <helib::Ctxt> max(const std::vector <helib::CtPtrs_vectorCt> & values);

    /**
     * Find the minimum value from an array, in a divide-et-impera manner to decrease operation circuit depth
    **/
    std::vector <helib::Ctxt> min(const std::vector <helib::CtPtrs_vectorCt> & values);

    /**
     * Bubble sort the encrypted data, it is sorted in increasing order by default
     * Comparator should return (encrypted) 1 when the elements are already in order, (encrypted) 0 otherwise
    **/
    void sort(std::vector <helib::CtPtrs_vectorCt> & to_sort, int len, 
                std::function <helib::Ctxt(helib::CtPtrs_vectorCt, helib::CtPtrs_vectorCt)> comparator = operator >);

    /**
     * Bellman-Ford implementation over graph with HElib-BGV encrypted weights
     * Returns ONLY ONE DISTANCE: from src to dst
     * The edges are considered unidirectional (first -> second, cost)
     * The nodes are considered to be in the interval [0, node count - 1]; if they have different values, a (temporary) conversion is needed
     * NOTE: DIST_BITLEN limits the infinity value representation, and, as a consequence, 
     *          EVERY WEIGHT IS ASSUMED TO BE LESS THAN ((1 << (DIST_BITLEN - 1)) / number of edges) - 1
    **/
    std::vector <helib::Ctxt> shortest_path_cost(const std::vector <std::tuple <int, int, helib::CtPtrs_vectorCt>> & edges, const int node_cnt,
                                                    const helib::CtPtrs_vectorCt & src, const helib::CtPtrs_vectorCt & dst, const int DIST_BITLEN = 8);

    /**
     * Bellman-Ford implementation over graph with HElib-BGV encrypted weights
     * Returns ALL distances from src
     * The edges are considered unidirectional (first -> second, cost)
     * The nodes are considered to be in the interval [0, node count - 1]; if they have different values, a (temporary) conversion is needed
     * NOTE: DIST_BITLEN limits the infinity value representation, and, as a consequence, 
     *          EVERY WEIGHT IS ASSUMED TO BE LESS THAN ((1 << (DIST_BITLEN - 1)) / number of edges) - 1
    **/
    std::vector <std::vector <helib::Ctxt>> shortest_path_cost(const std::vector <std::tuple <int, int, helib::CtPtrs_vectorCt>> & edges, const int node_cnt,
                                                    const helib::CtPtrs_vectorCt & src, const int DIST_BITLEN = 8);
}

#endif