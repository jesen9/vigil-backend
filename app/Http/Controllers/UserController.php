<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function login(Request $request)
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
                'user_id' => $user->id,
                'username' => $user->username,
                'token' => $token->accessToken,
                'plain_text' => explode("|",$token->plainTextToken)[1]
            ]);
        }

    }

    public function logout()
    {
        $user = Auth::user();
        $user->tokens()->delete();
        return response()->json([
            'status' => 'User logged out'
        ]);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function store(Request $request)
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

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }
}
