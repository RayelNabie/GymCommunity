<?php

use App\Models\Post;
use App\Models\User;

describe('Post Security', function () {
    describe('XSS Protection', function () {
        it('escapes script tags in post title and body', function () {
            $user = User::factory()->create();
            $xssTitle = '<script>alert("XSS Title")</script>';
            $xssBody = '<script>alert("XSS Body")</script>';

            $post = Post::factory()->create([
                'title' => $xssTitle,
                'body' => $xssBody,
            ]);

            $response = $this->actingAs($user)->get(route('artikelen.show', $post));

            $response->assertStatus(200);

            // We should NOT see the raw script tag (it implies it was rendered as HTML)
            // Note: assertDontSee searches for the raw string if escape is false.
            $response->assertDontSee($xssTitle, false);
            $response->assertDontSee($xssBody, false);

            // We SHOULD see the escaped version (safe to display)
            $response->assertSee(e($xssTitle), false);
            $response->assertSee(e($xssBody), false);
        });
    });

    describe('SQL Injection Protection', function () {
        it('returns 404 for malicious post ID injection', function () {
            $user = User::factory()->create();

            // Try to inject SQL into the route parameter
            // Since we use UUIDs and route model binding, this should just fail to find the model or 404.
            $maliciousId = '1 OR 1=1';

            $response = $this->actingAs($user)->get('/artikelen/'.$maliciousId);

            $response->assertStatus(404);
        });
    });
});
