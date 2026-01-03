<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;
use App\Http\Controllers\Auth\ConfirmablePasswordController;
use App\Http\Controllers\Auth\EmailVerificationNotificationController;
use App\Http\Controllers\Auth\EmailVerificationPromptController;
use App\Http\Controllers\Auth\NewPasswordController;
use App\Http\Controllers\Auth\PasswordController;
use App\Http\Controllers\Auth\PasswordResetLinkController;
use App\Http\Controllers\Auth\RegisteredUserController;
use App\Http\Controllers\Auth\VerifyEmailController;
use Illuminate\Support\Facades\Route;

/**
 * Publieke Auth Routes (Gasten)
 */
Route::middleware('guest')->group(function () {
    // Registratie
    Route::get('registreren', [RegisteredUserController::class, 'create'])->name('register');
    Route::post('registreren', [RegisteredUserController::class, 'store']);

    // Inloggen
    Route::get('inloggen', [AuthenticatedSessionController::class, 'create'])->name('login');
    Route::post('inloggen', [AuthenticatedSessionController::class, 'store']);

    // Wachtwoord herstel (Request)
    Route::get('wachtwoord-vergeten', [PasswordResetLinkController::class, 'create'])->name('password.request');
    Route::post('wachtwoord-vergeten', [PasswordResetLinkController::class, 'store'])->name('password.email');

    // Wachtwoord herstel (Reset)
    Route::get('wachtwoord-resetten/{token}', [NewPasswordController::class, 'create'])->name('password.reset');
    Route::post('wachtwoord-resetten', [NewPasswordController::class, 'store'])->name('password.store');
});

/**
 * Beveiligde Auth Routes (Ingelogd)
 */
Route::middleware('auth')->group(function () {
    // Email Verificatie
    Route::prefix('email')->name('verification.')->group(function () {
        Route::get('bevestigen', EmailVerificationPromptController::class)->name('notice');
        Route::get('bevestigen/{id}/{hash}', VerifyEmailController::class)
            ->middleware(['signed', 'throttle:6,1'])
            ->name('verify');
        Route::post('verificatie-notificatie', [EmailVerificationNotificationController::class, 'store'])
            ->middleware('throttle:6,1')
            ->name('send');
    });

    // Wachtwoord Bevestiging & Updates
    Route::get('bevestig-wachtwoord', [ConfirmablePasswordController::class, 'show'])->name('password.confirm');
    Route::post('bevestig-wachtwoord', [ConfirmablePasswordController::class, 'store']);
    Route::put('wachtwoord-bijwerken', [PasswordController::class, 'update'])->name('password.update');

    // Uitloggen
    Route::post('uitloggen', [AuthenticatedSessionController::class, 'destroy'])->name('logout');
});
