<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function login(Request $request): \Illuminate\Http\JsonResponse
    {
        if(isset($request->email)){

            $validation = [
                'email' => 'required',
                'password' => 'required',
            ];

            $validator = Validator::make($request->all(), $validation);

            if($validator->fails()) {
                return response()->json([
                    'message' => 'Email or Password input failure'
                ]);
            }

            $credentials=[
                'email' => $request->email,
                'password' => $request->password
            ];
        }
        else{

            $validation = [
                'username' => 'required',
                'password' => 'required',
            ];

            $validator = Validator::make($request->all(), $validation);

            if($validator->fails()) {
                return response()->json([
                    'message' => 'Username or Password input failure'
                ]);
            }

            $credentials=[
                'username' => $request->username,
                'password' => $request->password
            ];
        }

        if(!Auth::attempt($credentials)){
            return response()->json([
                'status' => 'Login Failed'
            ]);
        }else{
            $user = Auth::user();
            $token = $user->createToken($user->username.'-'.now());
            return response()->json([
                'message' => 'Login Success',
                'user_id' => $user->id,
                'username' => $user->username,
                'plain_text' => explode("|",$token->plainTextToken)[1]
            ]);
        }

    }

    public function logout(): \Illuminate\Http\JsonResponse
    {
        $user = Auth::user();
        $user->tokens()->delete();
        return response()->json([
            'status' => 'User logged out'
        ]);
    }

    public function store(Request $request): \Illuminate\Http\JsonResponse
    {
        $validation = [
            'username' => 'required',
            'email' => 'required',
            'password' => 'required',
        ];

        $validator = Validator::make($request->all(), $validation);

        if($validator->fails()) {
            return response()->json([
                'message' => 'All parameters must be filled!'
            ]);
        }

        if (User::where('email', '=', $request->email)->exists()) {
            return response()->json([
                'message' => 'Email is already in use!'
            ]);
        }
        else if (User::where('username', '=', $request->username)->exists()) {
            return response()->json([
                'message' => 'Username is already in use!'
            ]);
        }

        $user = new User();
        $user->username = $request->username;
        $user->email = $request->email;
//        $user->email_verified_at = $request->email_verified_at;
        $user->password = Hash::make($request->password);
//        $user->remember_token = $request->remember_token;
        $user->save();

        return response()->json([
            'message' => 'New user created!'
        ]);
    }
}
