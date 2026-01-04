<?php

namespace App\Http\Controllers\Admin;

use App\Enums\PermissionEnum;
use App\Enums\RoleEnum;
use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\UpdateUserRoleRequest;
use App\Models\Role;
use App\Models\User;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\RedirectResponse;
use Illuminate\View\View;

class UserController extends Controller
{
    use AuthorizesRequests;

    public function edit(User $user): View
    {
        $this->authorize('update', $user);

        return view('dashboard.admin.edit', [
            'user' => $user,
            'availableRoles' => Role::with('permissions')->get(),
            'permissions' => PermissionEnum::cases(),
        ]);
    }

    public function update(UpdateUserRoleRequest $request, User $user): RedirectResponse
    {
        $validated = $request->validated();
        $role = Role::where('name', $validated['role'])->firstOrFail();
        $user->roles()->sync([$role->getKey()]);

        /** @var RoleEnum $roleName */
        $roleName = $role->name;

        return redirect()
            ->route('admin.index', ['tab' => 'users'])
            ->with('success', "De rol van {$user->name} is bijgewerkt naar {$roleName->label()}.");
    }

    public function destroy(User $user): RedirectResponse
    {
        $this->authorize('delete', $user);
        $user->delete();

        return redirect()
            ->route('admin.index', ['tab' => 'users'])
            ->with('success', 'User has been successfully removed.');
    }
}
