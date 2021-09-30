# HElib_BGV_extended_ops
Proof-of-concept implementation of diverse operations on BGV encrypted data under HElib
* The code uses the original HElib: https://github.com/homenc/HElib
* The (current) operations are mostly implemented as described here: https://academiaromana.ro/sectii2002/proceedings/doc2015-3s/08-Togan.pdf </br>
* The bloom filter implementation was inspired by the idea presented here: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC5547447/ </br>
* The instantiation of the bloom filter class in the test file (bft.cpp) uses Murmur3 hash, implemented here: https://github.com/aappleby/smhasher

The following features are implemented:
#
* Equality (==, !=)
* Comparison (>, <)
* Ternary operator
# 
* Min, Max of 2 numbers
* Min, Max on vector of numbers
* Sorting (bubble sort)
* Levenshtein distance 
* Shortest Path for graph with encrypted edge weights (Bellman-Ford)
#
* Encrypted bloom filter (more details in the private_bloom_filter.h - test file bft.cpp)
#
