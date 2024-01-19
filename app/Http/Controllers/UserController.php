<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
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
//            $userRole = $user->role()->first();

//            if ($userRole) {
//                $this->scope = $userRole->role;
//            }

//            dd('$user', $user, '$userRole', $userRole, '$userRole->role', $userRole->role, '$this', $this, '$this->scope', $this->scope);

            $token = $user->createToken($user->username.'-'.now());
//            dd('$token', $token);
            return response()->json([
//                'token' => Auth::user()->createToken('testToken')->accessToken
                'token' => $token->accessToken
            ]);
        }

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
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
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
