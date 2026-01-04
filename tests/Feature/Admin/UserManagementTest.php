<?php

use App\Enums\RoleEnum;
use App\Models\User;
use Database\Seeders\AccessControlSeeder;

beforeEach(function () {
    $this->seed(AccessControlSeeder::class);
});

/**
 * HAPPY FLOWS
 */
describe('Admin User Management: Happy Flows', function () {

    it('allows an admin to view the edit page', function () {
        $admin = createAdmin();
        $user = User::factory()->create();

        $this->actingAs($admin)
            ->get(route('users.edit', $user))
            ->assertStatus(200)
            ->assertViewIs('dashboard.admin.edit')
            ->assertViewHas('user', $user);
    });

    it('allows an admin to update a users role', function () {
        $admin = createAdmin();
        $user = createUserWithRole(RoleEnum::MEMBER);

        $this->actingAs($admin)
            ->put(route('users.update', $user), [
                'role' => RoleEnum::MANAGER->value,
            ])
            ->assertRedirect(route('admin.index', ['tab' => 'users']))
            ->assertSessionHas('success');

        expect($user->fresh()->hasRole(RoleEnum::MANAGER))->toBeTrue();
    });

    it('allows an admin to delete a user', function () {
        $admin = createAdmin();
        $user = User::factory()->create();

        $this->actingAs($admin)
            ->delete(route('users.destroy', $user))
            ->assertRedirect(route('admin.index', ['tab' => 'users']))
            ->assertSessionHas('success');

        $this->assertModelMissing($user);
    });
});

/**
 * SAD FLOWS (Authorization & Validation)
 */
describe('Admin User Management: Sad Flows', function () {

    it('redirects guests to login when accessing admin routes', function () {
        $user = User::factory()->create();

        $this->get(route('users.edit', $user))->assertRedirect(route('login'));
        $this->delete(route('users.destroy', $user))->assertRedirect(route('login'));
    });

    it('forbids non-admin users from accessing management', function () {
        $member = createUserWithRole(RoleEnum::MEMBER);
        $target = User::factory()->create();

        $this->actingAs($member)
            ->get(route('users.edit', $target))
            ->assertForbidden();
    });

    it('fails validation when providing an invalid role', function () {
        $admin = createAdmin();
        $user = User::factory()->create();

        $this->actingAs($admin)
            ->put(route('users.update', $user), ['role' => 'invalid-role'])
            ->assertSessionHasErrors('role');
    });
    it('prevents an admin from deleting themselves', function () {
        $admin = createAdmin();

        $this->actingAs($admin)
            ->delete(route('users.destroy', $admin))
            ->assertForbidden();

        $this->assertModelExists($admin);
    });

    it('prevents an admin from demoting themselves', function () {
        $admin = createAdmin();
        $this->actingAs($admin)
            ->put(route('users.update', $admin), [
                'role' => RoleEnum::MEMBER->value,
            ])
            ->assertForbidden();

        expect($admin->fresh()->hasRole(RoleEnum::ADMIN))->toBeTrue();
    });

    it('escapes user input to prevent XSS in the dashboard', function () {
        $admin = createAdmin();
        $maliciousName = '<script>alert("xss")</script>';
        User::factory()->create(['name' => $maliciousName]);

        $this->actingAs($admin)
            ->get(route('admin.index', ['tab' => 'users']))
            ->assertSee(e($maliciousName), false)
            ->assertDontSee($maliciousName, false);
    });
});
