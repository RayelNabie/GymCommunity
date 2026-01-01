<?php

namespace App\Http\Requests\Posts;

use App\Enums\PostCategoryEnum;
use App\Models\Post;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Translation\PotentiallyTranslatedString;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Enum;

class PostUpdateRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        $hasPermission = false;
        $user = $this->user();

        /** @var Post|null $post */
        $post = $this->route('post');

        if ($user !== null && $post !== null && $user->can('update', $post)) {
            $hasPermission = true;
        }

        return $hasPermission;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, array<int, string|Enum|Closure|ValidationRule>>
     */
    public function rules(): array
    {
        /**
         * @param  string  $attribute
         * @param  mixed  $value
         * @param  Closure(string): PotentiallyTranslatedString  $fail
         */
        $HTMLFilter = function (string $attribute, mixed $value, Closure $fail): void {
            if (is_string($value) && $value !== strip_tags($value)) {
                $fail("Het veld {$attribute} mag geen HTML bevatten.");
            }
        };

        return [
            'title' => [
                'required',
                'string',
                'min:5',
                'max:255',
                $HTMLFilter,
            ],
            'body' => [
                'required',
                'string',
                'min:50',
                'max:50000',
                $HTMLFilter,
            ],
            'category' => [
                'required',
                Rule::enum(PostCategoryEnum::class),
            ],
            'image' => [
                'nullable',
                'image',
                'mimes:jpeg,png,jpg,webp',
                'max:2048',
            ],
        ];
    }
}
