<?php

use App\Enums\RoleEnum;
use App\Models\User;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;

beforeEach(function () {
    $this->seed(\Database\Seeders\AccessControlSeeder::class);
});

describe('Login Streak Tracking', function () {
    describe('Happy Flow', function () {
        it('sets the streak to 1 on the first login', function () {
            $user = User::factory()->create([
                'last_login_at' => null,
                'login_streak' => 0,
            ]);

            Event::dispatch(new Login('web', $user, false));

            $user->refresh();
            expect($user->login_streak)->toBe(1)
                ->and($user->last_login_at)->not->toBeNull();
        });

        it('increments the streak when logging in on the next day', function () {
            $now = Carbon::now();
            $yesterday = $now->copy()->subDay();
            
            $user = User::factory()->create([
                'last_login_at' => $yesterday,
                'login_streak' => 1,
            ]);

            Carbon::setTestNow($now);
            Event::dispatch(new Login('web', $user, false));

            $user->refresh();
            expect($user->login_streak)->toBe(2)
                ->and($user->last_login_at->isSameDay($now))->toBeTrue();
        });

        it('promotes the user to TRAINER after 30 consecutive days', function () {
            $now = Carbon::now();
            $yesterday = $now->copy()->subDay();
            
            $user = User::factory()->create([
                'last_login_at' => $yesterday,
                'login_streak' => 29,
            ]);

            expect($user->hasRole(RoleEnum::TRAINER))->toBeFalse();

            Carbon::setTestNow($now);
            Event::dispatch(new Login('web', $user, false));

            $user->refresh();
            expect($user->login_streak)->toBe(30)
                ->and($user->hasRole(RoleEnum::TRAINER))->toBeTrue();
        });
    });

    describe('Sad Flow', function () {
        it('does not increment the streak when logging in on the same day', function () {
            $now = Carbon::now();
            Carbon::setTestNow($now);

            $user = User::factory()->create([
                'last_login_at' => $now,
                'login_streak' => 1,
            ]);

            Event::dispatch(new Login('web', $user, false));

            $user->refresh();
            expect($user->login_streak)->toBe(1);
        });

        it('resets the streak to 1 when logging in after a missed day', function () {
            $now = Carbon::now();
            $twoDaysAgo = $now->copy()->subDays(2);
            
            $user = User::factory()->create([
                'last_login_at' => $twoDaysAgo,
                'login_streak' => 5,
            ]);

            Carbon::setTestNow($now);
            Event::dispatch(new Login('web', $user, false));

            $user->refresh();
            expect($user->login_streak)->toBe(1)
                ->and($user->last_login_at->isSameDay($now))->toBeTrue();
        });
    });
});
