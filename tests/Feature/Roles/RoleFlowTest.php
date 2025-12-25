<?php

use App\Enums\RoleEnum;
use App\Models\Role;
use App\Models\User;
use Database\Seeders\AccessControlSeeder;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function () {
    $this->seed(AccessControlSeeder::class);
});

describe('Happy Flow', function () {

    test('It can create a new role with valid data', function () {
        Role::where('name', RoleEnum::MEMBER->value)->delete();

        $role = Role::create([
            'name' => RoleEnum::MEMBER->value,
            'description' => 'Member Role',
        ]);

        expect($role)->toBeInstanceOf(Role::class)
            ->and($role->name)->toBe(RoleEnum::MEMBER)
            ->and($role->description)->toBe('Member Role')
            ->and($role->role_id)->toBeString(); // UUID check
    });

    test('It can assign a role to a user', function () {
        $user = User::factory()->create();
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();

        $role->users()->attach($user->user_id);

        expect($role->users)->toHaveCount(1)
            ->and($role->users->first()->user_id)->toBe($user->user_id);

        // Verify database state directly
        $this->assertDatabaseHas('user_role', [
            'user_id' => $user->user_id,
            'role_id' => $role->role_id,
        ]);
    });

    test('It can detach a role from a user', function () {
        $user = User::factory()->create();
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();
        $role->users()->attach($user->user_id);

        $role->users()->detach($user->user_id);

        expect($role->users()->count())->toBe(0);
        $this->assertDatabaseMissing('user_role', [
            'user_id' => $user->user_id,
            'role_id' => $role->role_id,
        ]);
    });
});

describe('Unhappy Flow', function () {

    test('It cannot create a role with a duplicate name', function () {

        // Expecting a QueryException due to unique constraint on 'name'
        expect(fn () => Role::create(['name' => RoleEnum::ADMIN->value]))
            ->toThrow(QueryException::class);
    });

    test('It cannot assign the same role to a user twice', function () {
        $user = User::factory()->create();
        $role = Role::where('name', RoleEnum::MANAGER->value)->first();

        $role->users()->attach($user->user_id);

        // Expecting QueryException due to primary key constraint on pivot table
        expect(fn () => $role->users()->attach($user->user_id))
            ->toThrow(QueryException::class);
    });

    test('It cannot assign a non-existent user to a role', function () {
        $role = Role::where('name', RoleEnum::TRAINER->value)->first();
        $fakeUserId = Str::uuid()->toString();

        // Expecting QueryException due to foreign key constraint
        expect(fn () => $role->users()->attach($fakeUserId))
            ->toThrow(QueryException::class);
    });
});

describe('Edge Cases', function () {

    test('It removes all user associations cascadingly when deleting a role', function () {
        $user1 = User::factory()->create();
        $user2 = User::factory()->create();
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();

        $role->users()->attach([$user1->user_id, $user2->user_id]);

        expect($role->users()->count())->toBe(2);

        $role->delete();

        $this->assertDatabaseMissing('roles', ['role_id' => $role->role_id]);
        $this->assertDatabaseMissing('user_role', ['role_id' => $role->role_id]);
    });

    test('It removes role associations cascadingly when deleting a user', function () {
        $user = User::factory()->create();
        $role = Role::where('name', RoleEnum::MEMBER->value)->first();

        $role->users()->attach($user->user_id);

        $user->delete();

        $this->assertDatabaseMissing('users', ['user_id' => $user->user_id]);
        $this->assertDatabaseMissing('user_role', ['user_id' => $user->user_id]);
        // Role should still exist
        $this->assertDatabaseHas('roles', ['role_id' => $role->role_id]);
    });
});
