<?php

namespace Database\Factories;

use App\Models\Role;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Role>
 */
class RoleFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->unique()->jobTitle(),
            'description' => fake()->sentence(),
        ];
    }

    /**
     * Indicate that the role should have permissions.
     */
    public function withPermissions(array $permissions = []): static
    {
        return $this->afterCreating(function (Role $role) use ($permissions) {
            foreach ($permissions as $permissionName) {
                $permission = \App\Models\Permission::firstOrCreate(['name' => $permissionName]);
                $role->permissions()->attach($permission);
            }
        });
    }
}
