<?php

use App\Models\User;

describe('Happy Flow', function () {
    it('can render the login screen', function () {
        $response = $this->get('/inloggen');

        $response->assertStatus(200);
    });

    it('allows users to authenticate using the login screen', function () {
        $user = User::factory()->create();

        $response = $this->post('/inloggen', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $this->assertAuthenticated();
        $response->assertRedirect(route('dashboard', absolute: false));
    });

    it('allows users to logout', function () {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->post('/uitloggen');

        $this->assertGuest();
        $response->assertRedirect('/');
    });
});

describe('Unhappy Flow', function () {
    it('does not authenticate users with invalid password', function () {
        $user = User::factory()->create();

        $this->post('/inloggen', [
            'email' => $user->email,
            'password' => 'wrong-password',
        ]);

        $this->assertGuest();
    });

    it('handles SQL injection attempts in email field safely', function () {
        $this->post('/inloggen', [
            'email' => "' OR '1'='1",
            'password' => 'password',
        ]);

        $this->assertGuest();
    });

    it('handles XSS attempts in email field safely', function () {
        $response = $this->post('/inloggen', [
            'email' => '<script>alert("XSS")</script>',
            'password' => 'password',
        ]);

        $this->assertGuest();
        $response->assertDontSee('<script>alert("XSS")</script>', false);
    });
});
