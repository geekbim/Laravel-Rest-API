<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;

class UserController extends Controller
{
    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Invalid credentials'], 300);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'Could not create token'], 500);
        }

        return response()->json(compact('token'));
    }

    public function register(Request $request)
    {
        $validator = Validator::make(
            $request->all(),
            [
                'name'              => 'required|string|max:255',
                'email'             => 'required|string|email|max:255|unique:users',
                'phone'             => 'required|string|min:10',
                'jenis_kelamin'     => 'required|string|max:255',
                'tanggal_lahir'     => 'required|date',
                'password'          => 'required|string|min:6|confirmed'
            ]
        );

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = User::create([
            'name'              => $request->get('name'),
            'email'             => $request->get('email'),
            'phone'             => $request->get('phone'),
            'jenis_kelamin'     => $request->get('jenis_kelamin'),
            'tanggal_lahir'     => $request->get('tanggal_lahir'),
            'password'          => Hash::make($request->get('password'))
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json(compact('user', 'token'), 201);
    }

    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());

            return response()->json([
                'message' => 'User successfully sign out'
            ]);
        } catch (TokenExpiredException $e) {
            return response()->json(['message' => 'Token expired'], 400);
        } catch (TokenInvalidException $e) {
            return response()->json(['message' => 'Token invalid'], 400);
        } catch (JWTException $e) {
            return response()->json(['message' => 'Not authorized'], 400);
        }
    }

    public function refresh()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            $token = JWTAuth::refresh($user);
    
            return $this->createNewToken($token);
        } catch (TokenExpiredException $e) {
            return response()->json(['message' => 'Token expired'], 400);
        } catch (TokenInvalidException $e) {
            return response()->json(['message' => 'Token invalid'], 400);
        } catch (JWTException $e) {
            return response()->json(['message' => 'Not authorized'], 400);
        }
    }

    public function getAuthenticatedUser()
    {
        try {
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['User not found'], 404);
            }
        } catch (TokenExpiredException $e) {
            return response()->json(['message' => 'Token expired'], 400);
        } catch (TokenInvalidException $e) {
            return response()->json(['message' => 'Token invalid'], 400);
        } catch (JWTException $e) {
            return response()->json(['message' => 'Not authorized'], 400);
        }

        return response()->json(compact('user'));
    }

    protected function createNewToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer', 
            'expires_in' => JWTAuth::factory()->getTTL() * 60,
            'user' => Auth::user()
        ]);
    }
}
