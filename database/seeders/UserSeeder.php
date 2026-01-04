<?php

namespace Database\Seeders;

use App\Enums\RoleEnum;
use App\Models\User;
use Illuminate\Database\Seeder;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        User::factory()
            ->withRole(RoleEnum::ADMIN->value)
            ->create([
                'name' => 'Admin User',
                'email' => 'admin@gym.nl',
                'password' => bcrypt('123456'),
            ]);

        User::factory(3)
            ->withRole(RoleEnum::MANAGER->value)
            ->create();

        User::factory(10)
            ->withRole(RoleEnum::TRAINER->value)
            ->create();

        User::factory(50)
            ->withRole(RoleEnum::MEMBER->value)
            ->create();
    }
}
