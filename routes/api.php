<?php

use App\Http\Controllers\DataController;
use App\Http\Controllers\NotesController;
use App\Http\Controllers\UserController;
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

Route::post('/login', [UserController::class, 'login']);
Route::get('/get-cve-list', [DataController::class, 'getCveList']);
Route::get('/get-cve-details', [DataController::class, 'getCveDetails']);
Route::get('/update-database', [DataController::class, 'updateDatabase']);


Route::middleware(['auth:api'])->group(function(){
    Route::post('/insert-notes', [DataController::class, 'insertNotes']);
    Route::get('/get-notes', [DataController::class, 'getNotes']);
    Route::delete('/delete-notes/{id}', [DataController::class, 'deleteNotes']);
});

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
