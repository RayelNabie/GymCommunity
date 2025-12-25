<?php

namespace Database\Seeders;

use App\Enums\PermissionEnum;
use App\Enums\RoleEnum;
use App\Models\Permission;
use App\Models\Role;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

class AccessControlSeeder extends Seeder
{
    /**
     * @throws Throwable
     */
    public function run(): void
    {
        DB::transaction(function () {
            $this->seedPermissions();
            $this->seedRoles();
        });
    }

    private function seedPermissions(): void
    {
        $now = now();

        $data = collect(PermissionEnum::cases())->map(fn (PermissionEnum $case) => [
            'permission_id' => Str::uuid()->toString(),
            'name' => $case->value,
            'description' => $case->description(),
            'created_at' => $now,
            'updated_at' => $now,
        ])->toArray();

        Permission::insertOrIgnore($data);
    }

    private function seedRoles(): void
    {
        $allPermissions = Permission::all();

        foreach (RoleEnum::cases() as $roleEnum) {
            $role = Role::firstOrCreate(
                ['name' => $roleEnum->value],
                ['description' => $roleEnum->label()]
            );

            $permissionValues = collect($roleEnum->permissions())->pluck('value')->toArray();

            $ids = $allPermissions
                ->filter(fn (Permission $permission) => in_array($permission->name->value, $permissionValues))
                ->pluck('permission_id');

            // Use sync to update db when changes in permission enums are made
            $role->permissions()->sync($ids);
        }
    }
}
