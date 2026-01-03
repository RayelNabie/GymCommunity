<?php

use App\Models\Post;
use App\Models\User;

use function Pest\Laravel\get;

describe('Happy Flow', function () {
    it('can search posts by title', function () {
        $user = User::factory()->create();

        Post::factory()->create([
            'user_id' => $user->user_id,
            'title' => 'Unique Searchable Title',
            'body' => 'Some body content',
        ]);

        Post::factory()->create([
            'user_id' => $user->user_id,
            'title' => 'Another Post',
            'body' => 'Some other content',
        ]);

        get(route('artikelen.index', ['search' => 'Unique']))
            ->assertOk()
            ->assertSee('Unique Searchable Title')
            ->assertDontSee('Another Post');
    });

    it('can search posts by body content', function () {
        $user = User::factory()->create();

        Post::factory()->create([
            'user_id' => $user->user_id,
            'title' => 'First Post',
            'body' => 'Hidden gem inside body',
        ]);

        Post::factory()->create([
            'user_id' => $user->user_id,
            'title' => 'Second Post',
            'body' => 'Nothing to see here',
        ]);

        get(route('artikelen.index', ['search' => 'gem']))
            ->assertOk()
            ->assertSee('First Post')
            ->assertDontSee('Second Post');
    });

    it('is case insensitive', function () {
        $user = User::factory()->create();

        Post::factory()->create([
            'user_id' => $user->user_id,
            'title' => 'UPPERCASE TITLE',
        ]);

        get(route('artikelen.index', ['search' => 'uppercase']))
            ->assertOk()
            ->assertSee('UPPERCASE TITLE');
    });
});

describe('Unhappy Flow', function () {
    it('shows no results message when search yields no matches', function () {
        $user = User::factory()->create();
        Post::factory()->create(['user_id' => $user->user_id, 'title' => 'Existing Post']);

        get(route('artikelen.index', ['search' => 'NonExistentTerm']))
            ->assertOk()
            ->assertDontSee('Existing Post')
            ->assertSee('Nog geen artikelen');
    });

    it('sanitizes search input to prevent XSS reflection', function () {
        // The search term is usually reflected in the search bar value
        $xss = '<script>alert(1)</script>';

        get(route('artikelen.index', ['search' => $xss]))
            ->assertOk()
            ->assertSee(e($xss), false) // Should see escaped version
            ->assertDontSee($xss, false); // Should not see raw version
    });

    it('handles SQL injection attempts safely', function () {
        $user = User::factory()->create();
        Post::factory()->create(['user_id' => $user->user_id, 'title' => 'Safe Post']);

        // A typical SQL injection payload that tries to make the condition always true
        $sqlInjection = "' OR '1'='1";

        // Because we use Eloquent/PDO bindings, this should be treated as a literal string search
        // So it should search for a post with title/body containing literally "' OR '1'='1"
        // It should NOT return all posts (unless one actually contains that string)
        // And definitely should NOT crash
        get(route('artikelen.index', ['search' => $sqlInjection]))
            ->assertOk()
            ->assertDontSee('Safe Post') // Should not find the post because the title doesn't match the injection string
            ->assertSee('Nog geen artikelen');
    });
});
