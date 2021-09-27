# HElib_BGV_extended_ops
(Demonstrative) implementation of diverse operations on BGV encrypted data under HElib
* The code uses the original HElib: https://github.com/homenc/HElib
* The (current) operations are mostly implemented as described here: https://academiaromana.ro/sectii2002/proceedings/doc2015-3s/08-Togan.pdf </br>

The following operations are implemented:
* Equality (==, !=)
* Comparison (>, <)
* Min, Max of 2 numbers
* Min, Max on vector of numbers
* Sorting
* Levenshtein distance 
* Shortest Path for graph with encrypted edge weights
* Encrypted bloom filter with "SIMD" plaintext isomorphism optimization utilization
