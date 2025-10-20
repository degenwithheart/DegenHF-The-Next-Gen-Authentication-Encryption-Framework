<?php

namespace DegenHF\EccAuth\Middleware;

use Closure;
use DegenHF\EccAuth\EccAuthService;
use Illuminate\Http\Request;

/**
 * ECC Authentication Middleware
 */
class EccAuthMiddleware
{
    private EccAuthService $eccAuthService;

    public function __construct(EccAuthService $eccAuthService)
    {
        $this->eccAuthService = $eccAuthService;
    }

    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'No authentication token provided'], 401);
        }

        try {
            $user = $this->eccAuthService->verifyToken($token);
            $request->merge(['user' => $user]);
            auth()->setUser((object) $user);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Invalid or expired token'], 401);
        }

        return $next($request);
    }
}