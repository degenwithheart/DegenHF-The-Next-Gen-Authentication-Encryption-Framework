<?php

namespace DegenHF\EccAuth\Tests;

use DegenHF\EccAuth\EccAuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\TestCase;

/**
 * ECC Authentication Service Test
 */
class EccAuthServiceTest extends TestCase
{
    private EccAuthService $eccAuthService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->eccAuthService = new EccAuthService(
            $this->app['cache.store'],
            [
                'hash_iterations' => 1000, // Lower for testing
                'token_expiry' => 3600,
                'cache_size' => 1000,
                'cache_ttl' => 60,
            ]
        );
    }

    /** @test */
    public function it_can_register_a_user()
    {
        $userId = $this->eccAuthService->register('testuser', 'testpass123');

        $this->assertNotEmpty($userId);
        $this->assertIsString($userId);
    }

    /** @test */
    public function it_throws_exception_for_duplicate_user()
    {
        $this->eccAuthService->register('testuser', 'testpass123');

        $this->expectException(\InvalidArgumentException::class);
        $this->eccAuthService->register('testuser', 'differentpass');
    }

    /** @test */
    public function it_can_authenticate_a_user()
    {
        $this->eccAuthService->register('testuser', 'testpass123');

        $token = $this->eccAuthService->authenticate('testuser', 'testpass123');

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }

    /** @test */
    public function it_throws_exception_for_invalid_password()
    {
        $this->eccAuthService->register('testuser', 'testpass123');

        $this->expectException(\RuntimeException::class);
        $this->eccAuthService->authenticate('testuser', 'wrongpass');
    }

    /** @test */
    public function it_can_verify_a_token()
    {
        $this->eccAuthService->register('testuser', 'testpass123');
        $token = $this->eccAuthService->authenticate('testuser', 'testpass123');

        $user = $this->eccAuthService->verifyToken($token);

        $this->assertIsArray($user);
        $this->assertEquals('testuser', $user['username']);
    }

    /** @test */
    public function it_throws_exception_for_invalid_token()
    {
        $this->expectException(\RuntimeException::class);
        $this->eccAuthService->verifyToken('invalid.token.here');
    }

    /** @test */
    public function it_can_create_a_session()
    {
        $this->eccAuthService->register('testuser', 'testpass123');
        $token = $this->eccAuthService->authenticate('testuser', 'testpass123');
        $user = $this->eccAuthService->verifyToken($token);

        $session = $this->eccAuthService->createSession($user['id']);

        $this->assertIsArray($session);
        $this->assertArrayHasKey('session_id', $session);
        $this->assertArrayHasKey('user_id', $session);
        $this->assertEquals($user['id'], $session['user_id']);
    }

    /** @test */
    public function it_can_get_a_session()
    {
        $this->eccAuthService->register('testuser', 'testpass123');
        $token = $this->eccAuthService->authenticate('testuser', 'testpass123');
        $user = $this->eccAuthService->verifyToken($token);

        $created = $this->eccAuthService->createSession($user['id']);
        $retrieved = $this->eccAuthService->getSession($created['session_id']);

        $this->assertIsArray($retrieved);
        $this->assertEquals($created['session_id'], $retrieved['session_id']);
    }

    protected function getPackageProviders($app)
    {
        return ['DegenHF\EccAuth\EccAuthServiceProvider'];
    }
}