<?php

namespace App\Http\Requests\Admin;

use App\Enums\RoleEnum;
use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Enum;

class UpdateUserRoleRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        $currentUser = $this->user();
        $userToUpdate = $this->route('user');

        if ($currentUser && $this->isMethod('PUT')) {
            return $currentUser->can('update', $userToUpdate);
        }

        return false;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, array<int, Enum|string>>
     */
    public function rules(): array
    {
        return [
            'role' => [
                'required',
                'string',
                Rule::enum(RoleEnum::class),
                'exists:roles,name',
            ],
        ];
    }
}
