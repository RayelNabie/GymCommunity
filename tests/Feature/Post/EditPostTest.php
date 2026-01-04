<?php

use App\Enums\PermissionEnum;
use App\Enums\RoleEnum;
use App\Models\Permission;
use App\Models\Post;
use App\Models\Role;
use App\Models\User;

describe('Happy Flow', function () {
    it('allows the owner to view the edit page', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->get(route('artikelen.edit', $post));

        $response->assertStatus(200);
        $response->assertViewIs('artikelen.edit');
        $response->assertViewHas('post');
    });

    it('allows a user with EDIT_ANY_POSTS permission to view the edit page', function () {
        $owner = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id]);

        $admin = User::factory()->create();
        $permission = Permission::create([
            'name' => PermissionEnum::EDIT_ANY_POSTS,
            'description' => PermissionEnum::EDIT_ANY_POSTS->description(),
        ]);
        $role = Role::create([
            'name' => RoleEnum::ADMIN,
            'description' => RoleEnum::ADMIN->label(),
        ]);
        $role->permissions()->attach($permission);
        $admin->roles()->attach($role);

        $response = $this->actingAs($admin)->get(route('artikelen.edit', $post));

        $response->assertStatus(200);
        $response->assertViewIs('artikelen.edit');
    });
});

describe('Unhappy Flow', function () {
    it('redirects guests to login page', function () {
        $post = Post::factory()->create();

        $response = $this->get(route('artikelen.edit', $post));

        $response->assertRedirect('/inloggen');
    });

    it('returns 403 when a user tries to edit another users post without permission', function () {
        $owner = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id]);

        $otherUser = User::factory()->create();

        $response = $this->actingAs($otherUser)->get(route('artikelen.edit', $post));

        $response->assertStatus(403);
    });
});
