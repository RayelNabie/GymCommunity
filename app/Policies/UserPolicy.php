<?php

namespace App\Policies;

use App\Enums\RoleEnum;
use App\Models\User;

class UserPolicy
{
    /**
     * Internal helper to check if a user has administrative privileges.
     */
    private function isAdmin(User $user): bool
    {
        return $user->hasRole(RoleEnum::ADMIN);
    }

    /**
     * Determine whether the user can access the admin dashboard.
     * Matches the 'can:viewAdminDashboard' middleware in web.php.
     */
    public function viewAdminDashboard(User $user): bool
    {
        return $this->isAdmin($user);
    }

    /**
     * Determine whether the user can view the list of all users.
     */
    public function viewAny(User $user): bool
    {
        return $this->isAdmin($user);
    }

    /**
     * Determine whether the user can view a specific user's details.
     */
    public function view(User $user, User $model): bool
    {
        // Admins can view anyone; users can view their own profile.
        return $this->isAdmin($user) || $user->is($model);
    }

    /**
     * Determine whether the user can update a specific user (e.g., change roles).
     */
    public function update(User $user): bool
    {
        return $this->isAdmin($user);
    }

    /**
     * Determine whether the user can delete a user account.
     */
    public function delete(User $user, User $model): bool
    {
        // Prevent admins from deleting their own account to avoid lockouts.
        return $this->isAdmin($user) && $user->isNot($model);
    }

    /**
     * Determine whether the user can restore a deleted user.
     */
    public function restore(User $user): bool
    {
        return $this->isAdmin($user);
    }

    /**
     * Determine whether the user can permanently delete a user.
     */
    public function forceDelete(User $user): bool
    {
        return $this->isAdmin($user);
    }
}
