<?php

use App\Enums\PostCategoryEnum;
use App\Models\Post;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('has correct primary key and uuid settings for Post', function () {
    $post = new Post;

    expect($post->getKeyName())->toBe('post_id')
        ->and($post->getIncrementing())->toBeFalse()
        ->and($post->getKeyType())->toBe('string');
});

it('has expected fillable attributes for Post', function () {
    $post = new Post;

    expect($post->getFillable())->toContain(
        'user_id',
        'title',
        'slug',
        'body',
        'category',
        'image'
    );
});

it('has user relationship', function () {
    $post = new Post;
    expect($post->user())->toBeInstanceOf(BelongsTo::class);
});

it('casts category to PostCategoryEnum', function () {
    $post = Post::factory()->create(['category' => PostCategoryEnum::KRACHT]);

    expect($post->category)->toBeInstanceOf(PostCategoryEnum::class)
        ->and($post->category)->toBe(PostCategoryEnum::KRACHT);
});

it('has working factory states', function () {
    $krachtPost = Post::factory()->kracht()->create();
    $cardioPost = Post::factory()->cardio()->create();
    $voedingPost = Post::factory()->voeding()->create();

    expect($krachtPost->category)->toBe(PostCategoryEnum::KRACHT)
        ->and($cardioPost->category)->toBe(PostCategoryEnum::CARDIO)
        ->and($voedingPost->category)->toBe(PostCategoryEnum::VOEDING);
});
