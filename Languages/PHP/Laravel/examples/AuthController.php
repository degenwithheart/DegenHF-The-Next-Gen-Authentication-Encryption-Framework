<?php

namespace App\Http\Controllers;

use DegenHF\EccAuth\Facades\EccAuth;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

/**
 * Example Authentication Controller
 */
class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $request->validate([
            'username' => 'required|string|max:255',
            'password' => 'required|string|min:8',
        ]);

        try {
            $userId = EccAuth::register(
                $request->input('username'),
                $request->input('password')
            );

            return response()->json([
                'success' => true,
                'userId' => $userId
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => $e->getMessage()
            ], 400);
        }
    }

    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        try {
            $token = EccAuth::authenticate(
                $request->input('username'),
                $request->input('password')
            );

            return response()->json([
                'success' => true,
                'token' => $token
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => $e->getMessage()
            ], 401);
        }
    }

    public function profile(Request $request): JsonResponse
    {
        return response()->json([
            'user' => $request->user()
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        // In a real application, you might want to blacklist the token
        return response()->json([
            'success' => true,
            'message' => 'Logged out successfully'
        ]);
    }
}