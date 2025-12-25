<?php

use App\Enums\PermissionEnum;
use App\Enums\RoleEnum;
use App\Models\Permission;
use App\Models\Role;
use Database\Seeders\AccessControlSeeder;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function () {
    $this->seed(AccessControlSeeder::class);
});

describe('Happy Flow', function () {

    test('It can attach a permission to a role', function () {
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();
        $permission = Permission::where('name', PermissionEnum::MANAGE_USERS->value)->first();

        $role->permissions()->attach($permission);

        expect($role->permissions)->toHaveCount(2) // 1 existing + 1 new
            ->and($role->permissions->pluck('permission_id'))->toContain($permission->permission_id);

        $this->assertDatabaseHas('permission_role', [
            'role_id' => $role->role_id,
            'permission_id' => $permission->permission_id,
        ]);
    });

    test('It can detach a permission from a role', function () {
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();
        $permission = Permission::where('name', PermissionEnum::BOOK_CLASSES->value)->first();

        // Ensure it's attached (seeded)
        expect($role->permissions->pluck('name'))->toContain(PermissionEnum::BOOK_CLASSES);

        $role->permissions()->detach($permission);

        expect($role->permissions()->count())->toBe(0);
        $this->assertDatabaseMissing('permission_role', [
            'role_id' => $role->role_id,
            'permission_id' => $permission->permission_id,
        ]);
    });

    test('It removes permission associations when deleting a role', function () {
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();
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
        $permission = Permission::where('name', PermissionEnum::BOOK_CLASSES->value)->first();
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();

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
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();
        $permission = Permission::where('name', PermissionEnum::BOOK_CLASSES->value)->first();

        // Already attached by seeder

        expect(fn () => $role->permissions()->attach($permission->permission_id))
            ->toThrow(QueryException::class);
    });

    test('It cannot attach a non-existent permission to a role', function () {
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();
        $fakePermissionId = Str::uuid()->toString();

        expect(fn () => $role->permissions()->attach($fakePermissionId))
            ->toThrow(QueryException::class);
    });
});

describe('Edge Cases', function () {

    test('It can attach many permissions to a role', function () {
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();
        $permissions = Permission::all();

        $role->permissions()->sync($permissions->pluck('permission_id'));

        expect($role->permissions)->toHaveCount($permissions->count());
    });

    test('It can attach many roles to a permission', function () {
        $permission = Permission::where('name', PermissionEnum::BOOK_CLASSES->value)->first();
        $roles = Role::all();

        // Sync all roles
        $permission->roles()->sync($roles->pluck('role_id'));

        expect($permission->roles)->toHaveCount($roles->count());
    });
});
