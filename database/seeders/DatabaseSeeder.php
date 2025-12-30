<?php

namespace Database\Seeders;

use App\Enums\RoleEnum;
use App\Models\Role;
use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    use WithoutModelEvents;

    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        $this->call([
            AccessControlSeeder::class,
        ]);

        // Create regular users
        $users = User::factory(10)->create();

        // Create admin user
        $adminUser = User::factory()->create([
            'name' => 'Admin',
            'email' => 'admin@example.com',
            'password' => 'password',
        ]);

        $adminRole = Role::where('name', RoleEnum::ADMIN->value)->first();

        if ($adminRole) {
            $adminUser->roles()->sync([$adminRole->getkey()]);
        }

        $this->call([
            PostSeeder::class,
        ]);
    }
}
