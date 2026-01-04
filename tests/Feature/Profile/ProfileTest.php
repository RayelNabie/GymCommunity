<?php

use App\Models\User;

test('profile page is displayed', function () {
    $user = User::factory()->create();

    $response = $this
        ->actingAs($user)
        ->get('/profiel');

    $response->assertOk();
});

test(/**
 * @throws JsonException
 */ 'profile information can be updated', function () {
    $user = User::factory()->create();

    $response = $this
        ->actingAs($user)
        ->patch('/profiel', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'phone_number' => '1234567890',
            'address' => 'Test Address 123',
            'date_of_birth' => '1990-01-01',
        ]);

    $response
        ->assertSessionHasNoErrors()
        ->assertRedirect('/profiel');

    $user->refresh();

    $this->assertSame('Test User', $user->name);
    $this->assertSame('test@example.com', $user->email);
    $this->assertSame('1234567890', $user->phone_number);
    $this->assertSame('Test Address 123', $user->address);
    $this->assertSame('1990-01-01', $user->date_of_birth->format('Y-m-d'));
    $this->assertNull($user->email_verified_at);
});

test('email verification status is unchanged when the email address is unchanged', function () {
    $user = User::factory()->create();

    $response = $this
        ->actingAs($user)
        ->patch('/profiel', [
            'name' => 'Test User',
            'email' => $user->email,
        ]);

    $response
        ->assertSessionHasNoErrors()
        ->assertRedirect('/profiel');

    $this->assertNotNull($user->refresh()->email_verified_at);
});

test('user can delete their account', function () {
    $user = User::factory()->create();

    $response = $this
        ->actingAs($user)
        ->delete('/profiel', [
            'password' => 'password',
        ]);

    $response
        ->assertSessionHasNoErrors()
        ->assertRedirect('/');

    $this->assertGuest();
    $this->assertNull($user->fresh());
});

test('correct password must be provided to delete account', function () {
    $user = User::factory()->create();

    $response = $this
        ->actingAs($user)
        ->from('/profiel')
        ->delete('/profiel', [
            'password' => 'wrong-password',
        ]);

    $response
        ->assertSessionHasErrorsIn('userDeletion', 'password')
        ->assertRedirect('/profiel');

    $this->assertNotNull($user->fresh());
});
