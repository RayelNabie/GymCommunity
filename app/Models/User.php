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
use Illuminate\Notifications\Notifiable;

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
            ->whereHas('permissions', fn ($query) => $query->where('name', $permission->value))
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
     * Filter users by role in a query
     *
     * @param  Builder<User>  $query
     */
    #[Scope]
    public function whereRole(Builder $query, RoleEnum $role): void
    {
        $query->whereHas('roles', fn ($q) => $q->where('name', $role->value));
    }

    /**
     * Filter users by permissions in a query
     *
     * @param  Builder<User>  $query
     */
    #[Scope]
    public function whereHasPermission(Builder $query, PermissionEnum $permission): void
    {
        $query->whereHas('roles.permissions', fn ($q) => $q->where('name', $permission->value));
    }
}
