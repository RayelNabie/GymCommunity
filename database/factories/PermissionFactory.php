<?php

namespace Database\Factories;

use App\Models\Permission;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Permission>
 */
class PermissionFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->unique()->word(),
            'description' => fake()->sentence(),
        ];
    }

    /**
     * Indicate that the permission should belong to roles.
     */
    public function withRoles(array $roles = []): static
    {
        return $this->afterCreating(function (Permission $permission) use ($roles) {
            foreach ($roles as $roleName) {
                $role = \App\Models\Role::firstOrCreate(['name' => $roleName]);
                $permission->roles()->attach($role);
            }
        });
    }
}
