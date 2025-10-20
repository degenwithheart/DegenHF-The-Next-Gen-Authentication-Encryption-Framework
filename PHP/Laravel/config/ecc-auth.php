<?php

return [
    /*
    |--------------------------------------------------------------------------
    | ECC Authentication Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for the ECC-based authentication system.
    | All values can be overridden with environment variables.
    |
    */

    'hash_iterations' => env('ECC_AUTH_HASH_ITERATIONS', 100000),

    'token_expiry' => env('ECC_AUTH_TOKEN_EXPIRY', 3600),

    'cache_size' => env('ECC_AUTH_CACHE_SIZE', 10000),

    'cache_ttl' => env('ECC_AUTH_CACHE_TTL', 300),
];