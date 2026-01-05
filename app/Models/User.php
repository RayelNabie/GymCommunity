<?php

namespace App\Models;

use App\Enums\PermissionEnum;
use App\Enums\RoleEnum;
use Database\Factories\UserFactory;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Carbon;

/**
 * @property Carbon|null $last_login_at
 * @property int $login_streak
 *
 * @method static Builder<static> search(string $searchTerm)
 * @method static Builder<static> whereRole(RoleEnum $role)
 * @method static Builder<static> whereHasPermission(PermissionEnum $permission)
 * @method static Builder<static> filteredForAdmin(Request $request)
 */
class User extends Authenticatable implements MustVerifyEmail
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, HasUuids, Notifiable;

    /**
     * @var string
     */
    protected $primaryKey = 'user_id';

    /**
     * Disable auto-incrementing since UUID's dont auto increment
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * Turn PK into string since UUID's aren't ints like normal id's
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'phone_number',
        'address',
        'date_of_birth',
        'last_login_at',
        'login_streak',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'date_of_birth' => 'date',
            'password' => 'hashed',
            'last_login_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsToMany<Role, $this>
     */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class, 'user_role', 'user_id', 'role_id')->withTimestamps();
    }

    /**
     * @return HasMany<Post, $this>
     */
    public function posts(): HasMany
    {
        return $this->hasMany(Post::class, 'user_id');
    }

    /**
     * Check if the current user instance has a specific permission
     */
    public function hasPermission(PermissionEnum $permission): bool
    {
        return $this->roles()
            ->whereHas('permissions', function ($query) use ($permission) {
                /** @phpstan-ignore-next-line Reason: PHPStan fails to infer that 'name' is a valid column on the related model. */
                $query->where('name', $permission->value);
            })
            ->exists();
    }

    /**
     * Check if the current user instance has a specific role
     */
    public function hasRole(RoleEnum $role): bool
    {
        return $this->roles()->where('name', $role->value)->exists();
    }

    /**
     *  Filter users by role in a query
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    #[Scope]
    public function whereRole(Builder $query, RoleEnum $role): Builder
    {
        $query->whereHas('roles', function ($q) use ($role) {
            /** @phpstan-ignore-next-line Reason: PHPStan fails to infer that 'name' is a valid column on the related model. */
            $q->where('name', $role->value);
        });

        return $query;
    }

    /**
     * Filter users by permissions in a query
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    #[Scope]
    public function whereHasPermission(Builder $query, PermissionEnum $permission): Builder
    {
        $query->whereHas('roles.permissions', function ($q) use ($permission) {
            /** @phpstan-ignore-next-line Reason: PHPStan fails to infer that 'name' is a valid column on the related model. */
            $q->where('name', $permission->value);
        });

        return $query;
    }

    /**
     * Filter users based on admin dashboard request inputs.
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    #[Scope]
    public function filteredForAdmin(Builder $query, Request $request): Builder
    {
        $query->with('roles');

        $search = $request->string('search')->trim()->toString();
        $role = $request->string('role')->trim()->toString();
        $permission = $request->string('permission')->trim()->toString();

        if ($search !== '') {
            /** @phpstan-ignore-next-line
             * Reason: Larastan 3.0 cannot resolve the #[Scope] attribute internally on the
             * Builder instance. Method search() is defined below and runtime-safe. */
            $this->search($query, $search);
        }

        if ($role !== '' && ($roleEnum = RoleEnum::tryFrom($role))) {
            /** @phpstan-ignore-next-line
             * Reason: Larastan 3.0 cannot resolve the #[Scope] attribute internally on the
             * Builder instance. Method search() is defined below and runtime-safe. */
            $this->whereRole($query, $roleEnum);
        }

        if ($permission !== '' && ($permEnum = PermissionEnum::tryFrom($permission))) {
            /** @phpstan-ignore-next-line
             * Reason: Larastan 3.0 cannot resolve the #[Scope] attribute internally on the
             * Builder instance. Method search() is defined below and runtime-safe. */
            $this->whereHasPermission($query, $permEnum);
        }

        return $query->latest();
    }

    /**
     * Filter users by name or email address.
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    #[Scope]
    public function search(Builder $query, string $searchTerm): Builder
    {
        $query->where(function (Builder $q) use ($searchTerm) {
            $q->where('name', 'like', "%{$searchTerm}%")
                ->orWhere('email', 'like', "%{$searchTerm}%");
        });

        return $query;
    }
}
