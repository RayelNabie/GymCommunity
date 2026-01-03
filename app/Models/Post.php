<?php

namespace App\Models;

use App\Enums\PostCategoryEnum;
use Database\Factories\PostFactory;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property string $post_id
 * @property string $user_id
 * @property string $title
 * @property string $slug
 * @property string $body
 * @property PostCategoryEnum $category
 * @property string|null $image
 *
 * @phpstan-type FilterInputs array{category?: string, search?: string, sort?: string}
 */
class Post extends Model
{
    /** @use HasFactory<Postfactory> */
    use HasFactory, HasUuids;

    /**
     * @var string
     */
    protected $primaryKey = 'post_id';

    /**
     * Disable auto-incrementing since UUID's dont auto increment
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * Turn PK into string since UUID's aren't ints like normal id's
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'title',
        'slug',
        'body',
        'category',
        'image',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'category' => PostCategoryEnum::class,
        ];
    }

    /**
     * Gets author of the post
     *
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'user_id');
    }

    /**
     * Scope the query to filter posts based on category and search terms.
     *
     * @param  Builder<Post>  $query
     * @param  array{category?: string, search?: string, sort?: string}  $filters
     */
    #[Scope]
    protected function filter(Builder $query, array $filters): void
    {
        if (! empty($filters['category'])) {
            $categoryValue = $filters['category'];
            $query->where('category', $categoryValue);
        }
        if (! empty($filters['search'])) {
            $searchTerm = $filters['search'];

            $query->where(function (Builder $subQuery) use ($searchTerm) {
                $subQuery->where('title', 'like', "%{$searchTerm}%")
                    ->orWhere('body', 'like', "%{$searchTerm}%");
            });
        }
    }
}
