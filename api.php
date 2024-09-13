<?php

use App\Http\Controllers\apiController;
use App\Http\Controllers\DemoController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth')->get('/user', function (Request $request) {
//   return $request->user();
// });
Route::middleware('auth')->prefix('api')->group(function () {

//   Route::controller(ApiController::class)->group(function () {

//             // For Encryption/Decryption
//             Route::post('encrypt', 'encrypt');
//             Route::post('decrypt', 'decrypt');


//             // Routes for Article
//             Route::post('add_article', 'addArticle'); 
//             Route::get('articlelist', 'articleList'); 
//             Route::get('article/{id}', 'getDataById');
//             Route::post('update_article', 'update_article');
//             //Route::put('update_article/{id}','Delete_article');
//             Route::post('Delete_article','Delete_article');
//             // Route::delete('Delete_article/{id}','Delete_article');
//   });
 });

Route::controller(apiController::class)->group(function () {
  
                    //User Authentication
                Route::post('register',  'register');
                Route::post('login',  'login');
                Route::post('logout',  'logout');

                // For Encryption/Decryption
                Route::post('encrypt', 'encrypt');
                Route::post('decrypt', 'decrypt');

                // Routes for Article
                Route::post('add_article', 'addArticle'); 
                Route::get('articlelist', 'articleList'); 
                Route::get('article/{id}', 'getDataById');
                Route::post('update_article', 'update_article');
                //Route::put('update_article/{id}','Delete_article');
                Route::post('Delete_article','Delete_article');
                // Route::delete('Delete_article/{id}','Delete_article');

});


