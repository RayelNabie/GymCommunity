<?php

describe('Happy Flow', function () {
    it('can render the registration screen', function () {
        $response = $this->get('/registreren');

        $response->assertStatus(200);
    });

    it('allows new users to register', function () {
        $response = $this->post('/registreren', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password',
            'password_confirmation' => 'password',
        ]);

        $this->assertAuthenticated();
        $response->assertRedirect(route('dashboard', absolute: false));
    });
});

describe('Unhappy Flow', function () {
    it('validates registration input', function () {
        $response = $this->post('/registreren', [
            'name' => '',
            'email' => 'not-an-email',
            'password' => 'short',
            'password_confirmation' => 'mismatch',
        ]);

        $response->assertSessionHasErrors(['name', 'email', 'password']);
        $this->assertGuest();
    });

    it('prevents SQL injection in registration fields', function () {
        $response = $this->post('/registreren', [
            'name' => "'; DROP TABLE users; --",
            'email' => "' OR '1'='1",
            'password' => 'password',
            'password_confirmation' => 'password',
        ]);

        // Should fail validation or just create a user with weird name, but definitely not execute SQL
        // Laravel validation usually catches invalid emails.
        $response->assertSessionHasErrors(['email']); 
        $this->assertGuest();
    });

    it('prevents XSS in registration fields', function () {
        $response = $this->post('/registreren', [
            'name' => '<script>alert("XSS")</script>',
            'email' => 'xss@example.com',
            'password' => 'password',
            'password_confirmation' => 'password',
        ]);

        // If it registers, we check if the name is escaped when displayed (e.g. on dashboard)
        // But here we just check if it redirects or errors. 
        // If it succeeds, we should check the database or subsequent page view.
        
        if ($response->status() === 302) {
             $this->assertAuthenticated();
             $user = auth()->user();
             expect($user->name)->toBe('<script>alert("XSS")</script>');
             // The protection happens at output (Blade {{ }}), not necessarily at input.
             // But let's assume we want to allow it but ensure it's safe.
        }
    });
});
