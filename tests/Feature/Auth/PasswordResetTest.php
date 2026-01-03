<?php

use App\Models\User;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Support\Facades\Notification;

describe('Happy Flow', function () {
    it('can render the reset password link screen', function () {
        $response = $this->get('/wachtwoord-vergeten');

        $response->assertStatus(200);
    });

    it('can request a reset password link', function () {
        Notification::fake();

        $user = User::factory()->create();

        $this->post('/wachtwoord-vergeten', ['email' => $user->email]);

        Notification::assertSentTo($user, ResetPassword::class);
    });

    it('can render the reset password screen', function () {
        Notification::fake();

        $user = User::factory()->create();

        $this->post('/wachtwoord-vergeten', ['email' => $user->email]);

        Notification::assertSentTo($user, ResetPassword::class, function ($notification) {
            $response = $this->get('/wachtwoord-resetten/'.$notification->token);

            $response->assertStatus(200);

            return true;
        });
    });

    it('can reset password with valid token', function () {
        Notification::fake();

        $user = User::factory()->create();

        $this->post('/wachtwoord-vergeten', ['email' => $user->email]);

        Notification::assertSentTo($user, ResetPassword::class, function ($notification) use ($user) {
            $response = $this->post('/wachtwoord-resetten', [
                'token' => $notification->token,
                'email' => $user->email,
                'password' => 'password',
                'password_confirmation' => 'password',
            ]);

            $response
                ->assertSessionHasNoErrors()
                ->assertRedirect(route('login'));

            return true;
        });
    });
});

describe('Unhappy Flow', function () {
    it('cannot request reset link with invalid email', function () {
        $response = $this->post('/wachtwoord-vergeten', ['email' => 'invalid-email']);

        $response->assertSessionHasErrors(['email']);
    });

    it('handles SQL injection in email for reset link', function () {
        $response = $this->post('/wachtwoord-vergeten', ['email' => "' OR '1'='1"]);

        $response->assertSessionHasErrors(['email']);
    });
});
