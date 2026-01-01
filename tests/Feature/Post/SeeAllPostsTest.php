<?php

use App\Models\Post;
use App\Models\User;

describe('Happy Flow', function () {
    it('can render the index page', function () {
        $user = User::factory()->create();
        Post::factory()->count(3)->create();

        $response = $this->get(route('artikelen.index'));

        $response->assertStatus(200);
        $response->assertViewIs('artikelen.index');
    });

    it('displays posts in latest order', function () {
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
    it('can render the index page with no posts', function () {
        $response = $this->get(route('artikelen.index'));

        $response->assertStatus(200);
        $response->assertSee('Nog geen artikelen');
        $response->assertSee('De community is nog even aan het opwarmen. Wees de eerste die zijn kennis deelt over krachttraining of voeding!');
    });
});
