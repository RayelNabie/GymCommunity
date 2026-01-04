<?php

namespace App\Http\Controllers\Admin;

use App\Enums\PermissionEnum;
use App\Enums\PostCategoryEnum;
use App\Enums\RoleEnum;
use App\Http\Controllers\Controller;
use App\Models\Post;
use App\Models\User;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Request;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\View\View;

class DashboardController extends Controller
{
    use AuthorizesRequests;

    public function index(Request $request): View
    {
        $this->authorize('viewAdminDashboard', User::class);

        $tab = $request->string('tab', 'users')->toString();

        $rawItems = match ($tab) {
            /** * We fetch the data first as mixed to handle the Larastan limitation with #[Scope].
             * @phpstan-ignore-next-line
             * Reason: Larastan 3.0 does not yet support the Laravel 12 #[Scope] attribute
             * on the Builder instance. The implementation is runtime-safe.
             */
            'posts' => Post::query()->filteredForAdmin($request)->paginate(15),

            /** * We fetch the data first as mixed to handle the Larastan limitation with #[Scope].
             * @phpstan-ignore-next-line
             * Reason: Larastan 3.0 does not yet support the Laravel 12 #[Scope] attribute
             * on the Builder instance. The implementation is runtime-safe.
             */
            default => User::query()->filteredForAdmin($request)->paginate(15),
        };

        /** @var LengthAwarePaginator<int, User|Post> $items */
        $items = $rawItems;

        return view('dashboard.admin.index', [
            'tab' => $tab,
            'items' => $items->withQueryString(),
            'roles' => RoleEnum::cases(),
            'permissions' => PermissionEnum::cases(),
            'categories' => PostCategoryEnum::cases(),
        ]);
    }
}
