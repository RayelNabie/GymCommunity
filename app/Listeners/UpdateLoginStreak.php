<?php

namespace App\Listeners;

use App\Enums\RoleEnum;
use App\Models\Role;
use App\Models\User;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Carbon;

class UpdateLoginStreak
{
    /**
     * Create the event listener.
     */
    public function __construct()
    {
        //
    }

    /**
     * Handle the event.
     */
    public function handle(Login $event): void
    {
        if (!$event->user instanceof User) {
            return;
        }

        $user = $event->user;

        if ($user->last_login_at?->isToday()) {
            $user->update(['last_login_at' => now()]);
            return;
        }

        $user->login_streak = $user->last_login_at?->isYesterday()
            ? $user->login_streak + 1
            : 1;

        $user->last_login_at = now();
        $user->save();

        if ($user->login_streak >= 30 && !$user->hasRole(RoleEnum::TRAINER)) {
            $trainerRole = Role::firstWhere('name', RoleEnum::TRAINER->value);

            if ($trainerRole) {
                $user->roles()->syncWithoutDetaching($trainerRole);
            }
        }
    }
}
