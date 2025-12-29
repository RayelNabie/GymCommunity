<?php

namespace Database\Factories;

use App\Enums\PostCategoryEnum;
use App\Models\Post;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<Post>
 */
class PostFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $title = fake()->sentence();

        return [
            'user_id' => User::factory(),
            'title' => $title,
            'slug' => Str::slug($title),
            'body' => fake()->paragraphs(5, true),
            'category' => fake()->randomElement(PostCategoryEnum::class),
            'image' => fake()->boolean(30) ? 'posts/'.fake()->uuid().'.jpg' : null,
        ];
    }

    // Enum States
    public function kracht(): static
    {
        return $this->state(['category' => PostCategoryEnum::KRACHT]);
    }

    public function cardio(): static
    {
        return $this->state(['category' => PostCategoryEnum::CARDIO]);
    }

    public function voeding(): static
    {
        return $this->state(['category' => PostCategoryEnum::VOEDING]);
    }

    public function recovery(): static
    {
        return $this->state(['category' => PostCategoryEnum::RECOVERY]);
    }
}
