<?php

use App\Http\Controllers\Admin\DashboardController as AdminDashboardController;
use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

Route::view('/', 'landing_page.index')->name('home');

Route::get('/mijn-artikelen', [DashboardController::class, 'index'])
    ->middleware(['auth', 'verified', 'throttle:60,1'])
    ->name('dashboard');

Route::prefix('artikelen')->name('artikelen.')->group(function () {
    // auth
    Route::middleware(['auth', 'verified', 'throttle:10,1'])->group(function () {
        Route::get('/nieuw-artikel', [PostController::class, 'create'])->name('create');
        Route::post('/', [PostController::class, 'store'])->name('store');
        Route::get('/{post}/aanpassen', [PostController::class, 'edit'])->name('edit');
        Route::put('/{post}', [PostController::class, 'update'])->name('update');
        Route::delete('/{post}', [PostController::class, 'destroy'])->name('destroy');
    });

    // public
    Route::middleware('throttle:60,1')->group(function () {
        Route::get('/', [PostController::class, 'index'])->name('index');
        Route::get('/{post}', [PostController::class, 'show'])->name('show');
    });
});

Route::middleware(['auth', 'throttle:20,1'])->group(function () {
    Route::get('/profiel', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profiel', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profiel', [ProfileController::class, 'destroy'])->name('profile.destroy');
});

Route::middleware(['auth', 'verified', 'can:viewAdminDashboard,App\Models\User'])->prefix('admin')->group(function () {
    Route::get('/', [AdminDashboardController::class, 'index'])->name('admin.index');

    Route::prefix('users')->name('users.')->group(function () {
        Route::get('/{user}/edit', [UserController::class, 'edit'])->name('edit');
        Route::put('/{user}', [UserController::class, 'update'])->name('update');
        Route::delete('/{user}', [UserController::class, 'destroy'])->name('destroy');
    });
});

require __DIR__.'/auth.php';
