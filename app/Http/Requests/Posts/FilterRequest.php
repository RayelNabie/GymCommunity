<?php

namespace App\Http\Requests\Posts;

use App\Enums\PostCategoryEnum;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Enum;

class FilterRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array{
     * category: array<int, Enum|string>,
     * search: array<int, string>,
     * sort: array<int, string>
     * }
     */
    public function rules(): array
    {
        return [
            'category' => ['nullable', Rule::enum(PostCategoryEnum::class)],
            'search' => ['nullable', 'string', 'max:100'],
            'sort' => ['nullable', 'string', 'in:new,old'],
        ];
    }
}
