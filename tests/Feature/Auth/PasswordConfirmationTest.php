<?php

use App\Models\User;

describe('Happy Flow', function () {
    it('can render the confirm password screen', function () {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->get('/bevestig-wachtwoord');

        $response->assertStatus(200);
    });

    it('can confirm password', function () {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->post('/bevestig-wachtwoord', [
            'password' => 'password',
        ]);

        $response->assertRedirect();
        $response->assertSessionHasNoErrors();
    });
});

describe('Unhappy Flow', function () {
    it('does not confirm password with invalid password', function () {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->post('/bevestig-wachtwoord', [
            'password' => 'wrong-password',
        ]);

        $response->assertSessionHasErrors();
    });
});
