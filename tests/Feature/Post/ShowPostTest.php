<?php

use App\Models\Post;
use App\Models\User;

describe('Happy Flow', function () {
    it('allows an authenticated user to view a post', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create();

        $response = $this->actingAs($user)->get(route('artikelen.show', $post));

        $response->assertStatus(200);
        $response->assertViewIs('artikelen.[slug]');
        $response->assertViewHas('post', function (Post $viewPost) use ($post) {
            return $viewPost->post_id === $post->post_id;
        });
    });

    it('displays the correct post information', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create([
            'title' => 'Specific Title',
            'body' => 'Specific Body Content',
        ]);

        $response = $this->actingAs($user)->get(route('artikelen.show', $post));

        $response->assertSee('Specific Title');
        $response->assertSee('Specific Body Content');
    });

    it('passes correct permissions to the view for the owner', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->get(route('artikelen.show', $post));

        $response->assertViewHas('canEdit', true);
        $response->assertViewHas('canDelete', true);
    });

    it('passes correct permissions to the view for other users', function () {
        $owner = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id]);
        $otherUser = User::factory()->create();

        $response = $this->actingAs($otherUser)->get(route('artikelen.show', $post));

        $response->assertViewHas('canEdit', false);
        $response->assertViewHas('canDelete', false);
    });

    it('allows the owner to view their inactive post', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id, 'is_active' => false]);

        $response = $this->actingAs($user)->get(route('artikelen.show', $post));

        $response->assertStatus(200);
        $response->assertSee($post->title);
    });

    it('allows viewing a post with query parameters in the URL', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create();

        $response = $this->actingAs($user)->get(route('artikelen.show', ['post' => $post, 'category' => 'kracht', 'search' => 'test']));

        $response->assertStatus(200);
        $response->assertViewIs('artikelen.[slug]');
        $response->assertViewHas('post', function (Post $viewPost) use ($post) {
            return $viewPost->post_id === $post->post_id;
        });
    });
});

describe('Unhappy Flow', function () {
    it('returns 404 for inactive post when viewed by another user', function () {
        $owner = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id, 'is_active' => false]);
        $otherUser = User::factory()->create();

        $response = $this->actingAs($otherUser)->get(route('artikelen.show', $post));

        $response->assertStatus(404);
    });

    it('returns 404 for inactive post when viewed by guest', function () {
        $post = Post::factory()->create(['is_active' => false]);

        $response = $this->get(route('artikelen.show', $post));

        $response->assertStatus(404);
    });

    it('allows guests to view a post', function () {
        $post = Post::factory()->create();

        $response = $this->get(route('artikelen.show', $post));

        $response->assertStatus(200);
        $response->assertViewHas('canEdit', false);
        $response->assertViewHas('canDelete', false);
    });

    it('does not show management options to guests', function () {
        $post = Post::factory()->create();

        $response = $this->get(route('artikelen.show', $post));

        $response->assertDontSee("Je kunt dit artikel beheren via 'Mijn Artikelen'.");
        $response->assertDontSee('Je bekijkt dit artikel met beheerdersrechten.');
    });

    it('returns 404 when trying to view a non-existent post', function () {
        $user = User::factory()->create();
        $nonExistentId = '00000000-0000-0000-0000-000000000000';

        $response = $this->actingAs($user)->get(route('artikelen.show', $nonExistentId));

        $response->assertStatus(404);
    });
    it('escapes HTML in the post content (XSS protection)', function () {
        $user = User::factory()->create();
        $xssPayload = '<script>alert("xss")</script>';

        // We manually create a post with raw HTML to simulate if it somehow got in DB
        // (even though our Store/Update validation prevents it, we want to ensure Output Encoding works too)
        $post = Post::factory()->create([
            'title' => 'Title '.$xssPayload,
            'body' => 'Body '.$xssPayload,
        ]);

        $response = $this->actingAs($user)->get(route('artikelen.show', $post));

        // Assert we see the escaped version
        $response->assertSee(e($xssPayload), false);

        // Assert we do NOT see the raw unescaped HTML tag
        $response->assertDontSee($xssPayload, false);
    });

    it('returns 404 for various SQL injection patterns in the URL', function (string $payload) {
        $user = User::factory()->create();

        // We construct the URL manually because route() might url-encode the parameter
        // But even if we pass it to route(), Laravel's router should handle it.
        // Let's try passing it as the ID.
        $response = $this->actingAs($user)->get('/artikelen/'.$payload);

        $response->assertStatus(404);
    })->with([
        ["' OR '1'='1"],
        ["' UNION SELECT 1,2,3 --"],
        ['1; DROP TABLE users'],
        ["1' AND 1=1 --"],
        ['%27%20OR%201=1'], // URL encoded
        ["admin' --"],
        ["' OR 1=1#"],
        ["' OR 1=1/*"],
    ]);
});
