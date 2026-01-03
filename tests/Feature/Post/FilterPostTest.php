<?php

use App\Enums\PostCategoryEnum;
use App\Models\Post;
use App\Models\User;

use function Pest\Laravel\get;

describe('Happy FLow', function () {
    it('shows posts for a selected category (happy flow)', function () {
        $user = User::factory()->create();

        Post::factory()->create([
            'user_id' => $user->user_id,
            'category' => PostCategoryEnum::KRACHT,
            'title' => 'Kracht Post',
        ]);

        Post::factory()->create([
            'user_id' => $user->user_id,
            'category' => PostCategoryEnum::CARDIO,
            'title' => 'Cardio Post',
        ]);

        get(route('artikelen.index', ['category' => 'kracht']))
            ->assertOk()
            ->assertSee('Kracht Post')
            ->assertDontSee('Cardio Post');
    });

    it('shows all posts when no category is selected (happy flow)', function () {
        $user = User::factory()->create();

        Post::factory()->create([
            'user_id' => $user->user_id,
            'category' => PostCategoryEnum::KRACHT,
            'title' => 'Kracht Post',
        ]);

        Post::factory()->create([
            'user_id' => $user->user_id,
            'category' => PostCategoryEnum::CARDIO,
            'title' => 'Cardio Post',
        ]);

        get(route('artikelen.index'))
            ->assertOk()
            ->assertSee('Kracht Post')
            ->assertSee('Cardio Post');
    });
});

describe('Sad Flow', function () {
    it('shows empty state when category has no posts (sad flow)', function () {
        $user = User::factory()->create();

        Post::factory()->create([
            'user_id' => $user->user_id,
            'category' => PostCategoryEnum::KRACHT,
            'title' => 'Kracht Post',
        ]);

        get(route('artikelen.index', ['category' => 'voeding']))
            ->assertOk()
            ->assertDontSee('Kracht Post')
            ->assertSee('Nog geen artikelen');
    });

    it('handles invalid category values gracefully (sad flow)', function () {
        get(route('artikelen.index', ['category' => 'invalid-category']))
            ->assertSessionHasErrors('category');
    });

    it('is safe from sql injection in category parameter', function () {
        $user = User::factory()->create();
        Post::factory()->create(['user_id' => $user->user_id]);

        $sqlInjection = "' OR '1'='1";

        // The validation layer should catch this because it's not a valid Enum value
        get(route('artikelen.index', ['category' => $sqlInjection]))
            ->assertSessionHasErrors('category');

        // Double check: ensure no database error occurred (500)
        // and we didn't expose all records if we were to bypass validation (hypothetically)
    });

    it('is safe from xss in category parameter', function () {
        $xssPayload = '<script>alert("XSS")</script>';

        // 1. Validation should reject it as it's not a valid Enum
        $response = get(route('artikelen.index', ['category' => $xssPayload]));

        $response->assertSessionHasErrors('category');

        // 2. Follow redirect to check content
        // We need to simulate following the redirect to see if the input is reflected unsafely
        $response = $this->followRedirects($response);

        // Ensure the raw script tag is NOT present in the HTML
        $response->assertDontSee($xssPayload, false);
    });
});



