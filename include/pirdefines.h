#define MAX_NUM_PER_VARIETY 10
#define VARIETY_NUM 5

// PIR params that have been negotiated
static uint64_t number_of_items = VARIETY_NUM * MAX_NUM_PER_VARIETY;
static uint64_t size_per_item = MAX_NUM_PER_VARIETY * 6; // in bytes 
static uint32_t N = 4096;
static uint32_t logt = 20; // t is coeff modular (plaintext modular) 
static uint32_t d = 2;     // dimension of the database Recommended values: (logt, d) = (20, 2)

// use symmetric encryption instead of public key (recommended for smaller query)
static bool use_symmetric = false;

// pack as many elements as possible into a BFV plaintext (recommended)
static bool use_batching = true;

static bool use_recursive_mod_switching = true;