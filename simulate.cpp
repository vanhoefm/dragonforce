// Possible optimizations:
// - First determine which passwords less than X loops. These can then be quickly dropped.
// - Or first determine which passwords require more than X loops, so they can then be dropped?
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <string>
#include <algorithm>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "sae.h"
#include "simulate.h"

