<?php

use App\Models\User;
use Illuminate\Support\Facades\Route;

describe('Happy Flow', function () {
    it('adds security headers to all key application routes in production', function (string $route, bool $requiresAuth) {
        // Ensure we are in production environment
        $this->app['env'] = 'production';

        if ($requiresAuth) {
            $user = User::factory()->create();
            $this->actingAs($user);
        }

        $response = $this->get($route);

        $response->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('Referrer-Policy', 'strict-origin')
            ->assertHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
            ->assertHeader('Permissions-Policy', 'autoplay=(), battery=(), cross-origin-isolated=(), execution-while-not-rendered=()')
            ->assertHeader('Content-Security-Policy');

        // Check CSP content specifically for nonce
        $csp = $response->headers->get('Content-Security-Policy');
        expect($csp)->toContain("script-src 'nonce-")
            ->toContain("'strict-dynamic'")
            ->toContain("object-src 'none'")
            ->toContain("base-uri 'none'")
            ->toContain("require-trusted-types-for 'script'");

    })->with([
        ['/', false],
        ['/login', false],
        ['/register', false],
        ['/artikelen', false],
        ['/dashboard', true],
        ['/profile', true],
        ['/artikelen/create', true],
    ]);
});

describe('Unhappy Flow', function () {
    it('adds security headers even when a page is not found (404) in production', function () {
        $this->app['env'] = 'production';
        $response = $this->get('/this-route-does-not-exist-and-should-return-404');

        $response->assertStatus(404)
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Content-Security-Policy');
    });

    it('adds security headers even when the application errors (500) in production', function () {
        $this->app['env'] = 'production';
        // Define a route that throws an exception
        Route::get('/test-error-route', function () {
            throw new Exception('Test Server Error');
        });

        $response = $this->get('/test-error-route');

        $response->assertStatus(500)
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Content-Security-Policy');
    });
});

describe('Local Environment', function () {
    it('does not add security headers in local environment', function () {
        $this->app['env'] = 'local';

        $response = $this->get('/');

        $response->assertStatus(200);

        // Headers should NOT be present
        expect($response->headers->has('Content-Security-Policy'))->toBeFalse()
            ->and($response->headers->has('Strict-Transport-Security'))->toBeFalse()
            ->and($response->headers->has('Permissions-Policy'))->toBeFalse();
    });
});
