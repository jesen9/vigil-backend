<?php

use App\Http\Controllers\DataController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::get('/getcvelist', [DataController::class, 'getCveList']);
Route::get('/getcvedetails', [DataController::class, 'getCveDetails']);
Route::get('/updateDatabase', [DataController::class, 'updateDatabase']);

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
