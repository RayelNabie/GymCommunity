<?php

namespace App\Enums;

enum RoleEnum: string
{
    case ADMIN = 'admin';
    case MANAGER = 'manager';
    case TRAINER = 'trainer';
    case MEMBER = 'member';

    public function label(): string
    {
        return match ($this) {
            self::ADMIN => 'Beheerder',
            self::MANAGER => 'Sportschooleigenaar',
            self::TRAINER => 'Personal trainer',
            self::MEMBER => 'Sporter',
        };
    }

    /**
     * @return array<int, PermissionEnum>
     */
    public function permissions(): array
    {
        return match ($this) {
            self::ADMIN => PermissionEnum::cases(),
            self::MANAGER => [
                PermissionEnum::MANAGE_CLASSES,
                PermissionEnum::MANAGE_USERS,
                PermissionEnum::VIEW_ANALYTICS,
                PermissionEnum::PUBLISH_POSTS,
                PermissionEnum::EDIT_ANY_POSTS,
                PermissionEnum::CREATE_POSTS,
            ],
            self::TRAINER => [
                PermissionEnum::MANAGE_CLASSES,
                PermissionEnum::CREATE_POSTS,
            ],
            self::MEMBER => [
                PermissionEnum::BOOK_CLASSES,
            ],
        };
    }
}
