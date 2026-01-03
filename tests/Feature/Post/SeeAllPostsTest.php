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
    it('escapes HTML in the post titles and bodies (XSS protection)', function () {
        $user = User::factory()->create();
        $xssPayload = '<script>alert("xss")</script>';

        Post::factory()->create([
            'user_id' => $user->user_id,
            'title' => 'Title '.$xssPayload,
            'body' => 'Body '.$xssPayload,
        ]);

        $response = $this->get(route('artikelen.index'));

        // Assert we see the escaped version
        $response->assertSee(e($xssPayload), false);

        // Assert we do NOT see the raw unescaped HTML tag
        $response->assertDontSee($xssPayload, false);
    });

    it('handles SQL injection in pagination parameters gracefully', function () {
        Post::factory()->count(20)->create();

        // Try to inject SQL into the page parameter
        $response = $this->get(route('artikelen.index', ['page' => "1' OR '1'='1"]));

        // Laravel's paginator casts page to int, so this should just load page 1 or fail validation safely
        // It definitely shouldn't crash with 500 or execute SQL
        $response->assertStatus(200);
    });

    it('maintains query parameters when paginating', function () {
        $user = User::factory()->create();
        Post::factory()->count(20)->create(['user_id' => $user->user_id]);

        $response = $this->get(route('artikelen.index', ['category' => 'kracht', 'search' => 'test', 'page' => 2]));

        $response->assertStatus(200);
        // Verify the query string is preserved in pagination links
        $response->assertSee('category=kracht');
        $response->assertSee('search=test');
    });
});
