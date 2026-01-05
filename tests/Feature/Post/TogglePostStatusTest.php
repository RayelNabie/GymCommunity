<?php

use App\Enums\RoleEnum;
use App\Models\Permission;
use App\Models\Post;
use App\Models\Role;
use App\Models\User;

describe('Toggle Post Status', function () {
    it('allows the owner to toggle the active status of their post', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id, 'is_active' => true]);

        $response = $this->actingAs($user)->patch(route('artikelen.toggle-active', $post));

        $response->assertRedirect();
        $response->assertSessionHas('success');

        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'is_active' => false,
        ]);

        // Toggle back
        $response = $this->actingAs($user)->patch(route('artikelen.toggle-active', $post));
        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'is_active' => true,
        ]);
    });

    it('allows an admin to toggle the active status of any post', function () {
        $admin = User::factory()->create();
        $role = Role::create(['name' => RoleEnum::ADMIN->value]);
        $admin->roles()->attach($role);

        // Give admin permission to edit any posts (implied by admin role usually, but let's be safe based on policy)
        // Looking at PostPolicy: before() checks for ADMIN role. So role is enough.

        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id, 'is_active' => true]);

        $response = $this->actingAs($admin)->patch(route('artikelen.toggle-active', $post));

        $response->assertRedirect();
        $response->assertSessionHas('success');

        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'is_active' => false,
        ]);
    });

    it('does not allow a regular user to toggle someone else\'s post', function () {
        $owner = User::factory()->create();
        $otherUser = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id, 'is_active' => true]);

        $response = $this->actingAs($otherUser)->patch(route('artikelen.toggle-active', $post));

        $response->assertForbidden();

        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'is_active' => true,
        ]);
    });

    it('does not allow a guest to toggle a post', function () {
        $post = Post::factory()->create(['is_active' => true]);

        $response = $this->patch(route('artikelen.toggle-active', $post));

        $response->assertRedirect(route('login'));

        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'is_active' => true,
        ]);
    });
});
