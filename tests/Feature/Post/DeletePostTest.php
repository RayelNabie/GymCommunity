<?php

use App\Enums\PermissionEnum;
use App\Models\Post;
use App\Models\User;

beforeEach(function () {
    // Seed permissions if necessary, or just rely on factories if they handle it.
    // Assuming AccessControlSeeder is needed or factories do it.
    // For now, we'll just use factories and assume standard Laravel policies.
    $this->seed(\Database\Seeders\AccessControlSeeder::class);
});

describe('Happy Flow', function () {
    it('allows the owner to delete their own post', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->delete(route('artikelen.destroy', $post));

        $response->assertRedirect(route('artikelen.index'));
        $response->assertSessionHas('success', 'Dit artikel is definitief verwijderd.');
        $this->assertDatabaseMissing('posts', ['post_id' => $post->post_id]);
    });

    it('allows a user with EDIT_ANY_POSTS permission to delete another users post', function () {
        $owner = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id]);

        $admin = User::factory()->create();

        $permission = \App\Models\Permission::firstOrCreate(['name' => PermissionEnum::EDIT_ANY_POSTS->value]);
        $role = \App\Models\Role::firstOrCreate(['name' => 'admin']);
        $role->permissions()->syncWithoutDetaching([$permission->permission_id]);
        $admin->roles()->attach($role);

        $response = $this->actingAs($admin)->delete(route('artikelen.destroy', $post));

        $response->assertRedirect(route('artikelen.index'));
        $response->assertSessionHas('success', 'Dit artikel is definitief verwijderd.');
        $this->assertDatabaseMissing('posts', ['post_id' => $post->post_id]);
    });
});

describe('Unhappy Flow', function () {
    it('redirects guests to login page when trying to delete', function () {
        $post = Post::factory()->create();

        $response = $this->delete(route('artikelen.destroy', $post));

        $response->assertRedirect(route('login'));
        $this->assertDatabaseHas('posts', ['post_id' => $post->post_id]);
    });

    it('returns 403 when a user tries to delete another users post without permission', function () {
        $owner = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id]);

        $otherUser = User::factory()->create();

        $response = $this->actingAs($otherUser)->delete(route('artikelen.destroy', $post));

        $response->assertStatus(403);
        $this->assertDatabaseHas('posts', ['post_id' => $post->post_id]);
    });
    it('returns 404 for various SQL injection patterns in the URL', function (string $payload) {
        $user = User::factory()->create();

        // We construct the URL manually because route() might url-encode the parameter
        // But even if we pass it to route(), Laravel's router should handle it.
        // Let's try passing it as the ID.
        $response = $this->actingAs($user)->delete('/artikelen/'.$payload);

        $response->assertStatus(404);
    })->with([
        ["' OR '1'='1"],
        ["' UNION SELECT 1,2,3 --"],
        ['1; DROP TABLE users'],
        ["1' AND 1=1 --"],
        ['%27%20OR%201=1'], // URL encoded
        ["admin' --"],
        ["' OR 1=1#"],
        ["' OR 1=1/*"],
    ]);
});
