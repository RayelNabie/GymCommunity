<?php

use App\Models\Post;
use App\Models\User;
use Database\Seeders\DatabaseSeeder;
use Database\Seeders\PostSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('creates posts for existing users when running PostSeeder', function () {
    // Arrange
    $users = User::factory(3)->create();

    // Act
    $this->seed(PostSeeder::class);

    // Assert
    // Each user should have between 2 and 5 posts
    foreach ($users as $user) {
        expect($user->posts()->count())->toBeGreaterThanOrEqual(2)
            ->and($user->posts()->count())->toBeLessThanOrEqual(5);
    }

    expect(Post::count())->toBeGreaterThanOrEqual(6); // 3 users * min 2 posts
});

it('runs the database seeder successfully', function () {
    // Act
    $this->seed(DatabaseSeeder::class);

    // Assert
    // Check for users (1 admin + 3 managers + 10 trainers + 50 members = 64)
    expect(User::count())->toBe(64);

    // Check for admin user
    $admin = User::where('email', 'admin@gym.nl')->first();
    expect($admin)->not->toBeNull()
        ->and($admin->name)->toBe('Admin User')
        ->and(Post::count())->toBeGreaterThan(0);

    // Check that posts were seeded
});
