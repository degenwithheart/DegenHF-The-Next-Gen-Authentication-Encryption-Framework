<?php

namespace DegenHF\EccAuth\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * ECC Authentication Facade
 */
class EccAuth extends Facade
{
    protected static function getFacadeAccessor()
    {
        return \DegenHF\EccAuth\EccAuthService::class;
    }
}