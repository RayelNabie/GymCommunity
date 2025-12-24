<?php

use App\Models\Role;
use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

describe('Happy Flow', function () {

    test('It has expected tables and columns for roles and permissions schema', function () {
        expect(Schema::hasTable('roles'))->toBeTrue()
            ->and(Schema::hasTable('permissions'))->toBeTrue()
            ->and(Schema::hasTable('user_role'))->toBeTrue()
            ->and(Schema::hasTable('permission_role'))->toBeTrue()
            ->and(Schema::hasColumns('roles', ['role_id', 'name', 'description', 'created_at', 'updated_at']))->toBeTrue()
            ->and(Schema::hasColumns('permissions', ['permission_id', 'name', 'description', 'created_at', 'updated_at']))->toBeTrue()
            ->and(Schema::hasColumns('user_role', ['user_id', 'role_id', 'created_at', 'updated_at']))->toBeTrue()
            ->and(Schema::hasColumns('permission_role', ['permission_id', 'role_id', 'created_at', 'updated_at']))->toBeTrue();
    });

    test('It can attach and detach roles to a user via User relation', function () {
        $user = User::factory()->create();
        $role = Role::create([
            'name' => 'editor',
            'description' => 'Editor role',
        ]);

        // Attach role to user
        $user->roles()->attach($role->getKey());

        expect($user->roles()->count())->toBe(1)
            ->and($user->roles->first()->role_id)->toBe($role->role_id)
            ->and(DB::table('user_role')->where('user_id', $user->getKey())->where('role_id', $role->getKey())->exists())
            ->toBeTrue();

        // Detach
        $user->roles()->detach($role->getKey());
        expect($user->roles()->count())->toBe(0);
    });

    test('It removes pivot entries when a user is deleted (cascade)', function () {
        $user = User::factory()->create();
        $role = Role::create([
            'name' => 'moderator',
            'description' => 'Moderator role',
        ]);

        $role->users()->attach($user->getKey());
        expect(DB::table('user_role')->count())->toBe(1);

        $user->delete();

        expect(DB::table('user_role')->count())->toBe(0);
    });

    test('It removes pivot entries when a role is deleted (cascade)', function () {
        $user = User::factory()->create();
        $role = Role::create([
            'name' => 'contributor',
            'description' => 'Contributor role',
        ]);

        $role->users()->attach($user->getKey());
        expect(DB::table('user_role')->count())->toBe(1);

        $role->delete();

        expect(DB::table('user_role')->count())->toBe(0);
    });
});

describe('Unhappy Flow', function () {

    test('It cannot attach the same role to a user twice', function () {
        $user = User::factory()->create();
        $role = Role::factory()->create();

        $user->roles()->attach($role->role_id);

        expect(fn () => $user->roles()->attach($role->role_id))
            ->toThrow(QueryException::class);
    });

    test('It cannot attach a non-existent role to a user', function () {
        $user = User::factory()->create();
        $fakeRoleId = Str::uuid()->toString();

        expect(fn () => $user->roles()->attach($fakeRoleId))
            ->toThrow(QueryException::class);
    });
});

describe('Edge Cases', function () {

    test('Its users can have many roles', function () {
        $user = User::factory()->create();
        $roles = Role::factory()->count(5)->create();

        $user->roles()->attach($roles->pluck('role_id'));

        expect($user->roles)->toHaveCount(5);
    });
});
