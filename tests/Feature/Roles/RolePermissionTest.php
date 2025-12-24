<?php

use App\Models\Permission;
use App\Models\Role;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

describe('Happy Flow', function () {

    test('It can attach a permission to a role', function () {
        $role = Role::factory()->create();
        $permission = Permission::factory()->create();

        $role->permissions()->attach($permission);

        expect($role->permissions)->toHaveCount(1)
            ->and($role->permissions->first()->permission_id)->toBe($permission->permission_id);

        $this->assertDatabaseHas('permission_role', [
            'role_id' => $role->role_id,
            'permission_id' => $permission->permission_id,
        ]);
    });

    test('It can detach a permission from a role', function () {
        $role = Role::factory()->create();
        $permission = Permission::factory()->create();
        $role->permissions()->attach($permission);

        $role->permissions()->detach($permission);

        expect($role->permissions()->count())->toBe(0);
        $this->assertDatabaseMissing('permission_role', [
            'role_id' => $role->role_id,
            'permission_id' => $permission->permission_id,
        ]);
    });

    test('It can use factory helper to create role with permissions', function () {
        $role = Role::factory()->withPermissions(['edit_posts', 'delete_posts'])->create();

        expect($role->permissions)->toHaveCount(2)
            ->and($role->permissions->pluck('name'))->toContain('edit_posts', 'delete_posts');
    });

    test('It can use factory helper to create permission with roles', function () {
        $permission = Permission::factory()->withRoles(['admin', 'editor'])->create();

        expect($permission->roles)->toHaveCount(2)
            ->and($permission->roles->pluck('name'))->toContain('admin', 'editor');
    });

    test('It removes permission associations when deleting a role', function () {
        $role = Role::factory()->withPermissions(['view_dashboard'])->create();
        $permission = $role->permissions->first();

        $role->delete();

        $this->assertDatabaseMissing('permission_role', [
            'role_id' => $role->role_id,
            'permission_id' => $permission->permission_id,
        ]);

        // Permission itself should still exist
        $this->assertDatabaseHas('permissions', ['permission_id' => $permission->permission_id]);
    });

    test('It removes role associations when deleting a permission', function () {
        $permission = Permission::factory()->withRoles(['manager'])->create();
        $role = $permission->roles->first();

        $permission->delete();

        $this->assertDatabaseMissing('permission_role', [
            'role_id' => $role->role_id,
            'permission_id' => $permission->permission_id,
        ]);

        // Role itself should still exist
        $this->assertDatabaseHas('roles', ['role_id' => $role->role_id]);
    });
});

describe('Unhappy Flow', function () {

    test('It cannot attach the same permission to a role twice', function () {
        $role = Role::factory()->create();
        $permission = Permission::factory()->create();

        $role->permissions()->attach($permission->permission_id);

        expect(fn () => $role->permissions()->attach($permission->permission_id))
            ->toThrow(QueryException::class);
    });

    test('It cannot attach a non-existent permission to a role', function () {
        $role = Role::factory()->create();
        $fakePermissionId = Str::uuid()->toString();

        expect(fn () => $role->permissions()->attach($fakePermissionId))
            ->toThrow(QueryException::class);
    });
});

describe('Edge Cases', function () {

    test('It can attach many permissions to a role', function () {
        $role = Role::factory()->create();
        $permissions = Permission::factory()->count(10)->create();

        $role->permissions()->attach($permissions->pluck('permission_id'));

        expect($role->permissions)->toHaveCount(10);
    });

    test('It can attach many roles to a permission', function () {
        $permission = Permission::factory()->create();
        $roles = Role::factory()->count(10)->create();

        $permission->roles()->attach($roles->pluck('role_id'));

        expect($permission->roles)->toHaveCount(10);
    });
});
