<?php

namespace DegenHF\EccAuth;

use Illuminate\Support\ServiceProvider;

/**
 * ECC Authentication Service Provider
 */
class EccAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ecc-auth.php', 'ecc-auth');

        $this->app->singleton(EccAuthService::class, function ($app) {
            return new EccAuthService(
                $app['cache.store'],
                $app['config']['ecc-auth']
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/ecc-auth.php' => config_path('ecc-auth.php'),
        ], 'config');

        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'migrations');
    }
}