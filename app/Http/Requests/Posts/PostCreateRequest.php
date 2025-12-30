<?php

namespace App\Http\Requests\Posts;

use App\Enums\PostCategoryEnum;
use App\Models\Post;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Enum;

class PostCreateRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        $hasPermission = false;

        $user = $this->user();

        if ($user !== null && $user->can('create', Post::class)) {
            $hasPermission = true;
        }

        if ($hasPermission) {
            return true;
        }

        return false;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, array<int, string|Enum|Closure|ValidationRule>>
     */
    public function rules(): array
    {
        $HTMLFilter = function (string $attribute, mixed $value, Closure $fail) {
            if (is_string($value) && $value !== strip_tags($value)) {
                $fail('attribute cannot have HTML attributes');
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
                $HTMLFilter,
            ],
            'image' => [
                'nullable',
                'image',
                'mimes:jpeg,png,jpg,webp',
                'max:2048', // 2MB limit to protect against zip bombs
            ],
        ];
    }
}
