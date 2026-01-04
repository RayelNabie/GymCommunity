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
use Illuminate\Http\Request;

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
 *
 * @method static \Illuminate\Database\Eloquent\Builder|Post search(?string $term)
 * @method static \Illuminate\Database\Eloquent\Builder|Post category(?string $category)
 * @method static \Illuminate\Database\Eloquent\Builder|Post myarticle(bool $active = false)
 * @method static \Illuminate\Database\Eloquent\Builder|Post filteredForAdmin(\Illuminate\Http\Request $request)
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
     * Scope the query to filter posts based on search terms.
     *
     * @param  Builder<Post>  $query
     * @return Builder<Post>
     */
    #[Scope]
    public function search(Builder $query, ?string $term): Builder
    {
        if ($term) {
            $query->where(function (Builder $subQuery) use ($term) {
                $subQuery->where('title', 'like', "%$term%")
                    ->orWhere('body', 'like', "%$term%");
            });
        }

        return $query;
    }

    /**
     * Scope the query to filter posts based on category.
     *
     * @param  Builder<Post>  $query
     * @return Builder<Post>
     */
    #[Scope]
    public function category(Builder $query, ?string $category): Builder
    {
        if ($category) {
            $query->where('category', $category);
        }

        return $query;
    }

    /**
     * Scope the query to filter posts based on user_id.
     *
     * @param  Builder<Post>  $query
     * @return Builder<Post>
     */
    #[Scope]
    public function myarticle(Builder $query, bool $active = false): Builder
    {
        if ($active && auth()->check()) {
            $query->where('user_id', auth()->id());
        }

        return $query;
    }

    /**
     * Filter posts based on admin dashboard request inputs.
     *
     * @param  Builder<Post>  $query
     * @return Builder<Post>
     */
    #[Scope]
    public function filteredForAdmin(Builder $query, Request $request): Builder
    {
        $category = $request->string('category')->trim();
        $search = $request->string('search')->trim();

        $query->with('user');

        if ($category->isNotEmpty()) {
            /** @phpstan-ignore-next-line Reason: Larastan cannot resolve #[Scope] methods on the Builder instance. */
            $query->category($category->toString());
        }

        if ($search->isNotEmpty()) {
            /** @phpstan-ignore-next-line Reason: Larastan cannot resolve #[Scope] methods on the Builder instance. */
            $query->search($search->toString());
        }

        return $query->latest();
    }
}
