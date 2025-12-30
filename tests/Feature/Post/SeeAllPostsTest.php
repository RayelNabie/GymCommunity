<?php

use App\Models\Post;
use App\Models\User;

describe('Happy Flow', function () {
    test('It can access the index page', function () {
        $response = $this->get(route('artikelen.index'));

        $response->assertStatus(200);
        $response->assertViewIs('artikelen.index');
    });

    test('It displays posts in latest order', function () {
        $user = User::factory()->create(['name' => 'Test Author']);

        $oldPost = Post::factory()->create([
            'user_id' => $user->user_id,
            'title' => 'Old Post',
            'created_at' => now()->subDay(),
        ]);

        $newPost = Post::factory()->create([
            'user_id' => $user->user_id,
            'title' => 'New Post',
            'created_at' => now(),
        ]);

        $response = $this->get(route('artikelen.index'));

        $response->assertStatus(200);
        $response->assertSeeInOrder(['New Post', 'Old Post']);
        $response->assertSee('Test Author');
        $response->assertSee($newPost->category->label());
    });
});

describe('Unhappy Flow', function () {
    test('It displays an empty state when no posts exist', function () {
        $response = $this->get(route('artikelen.index'));

        $response->assertStatus(200);
        $response->assertSee('Geen posts gevonden');
        $response->assertSee('Er zijn nog geen posts geplaatst');
    });
});
