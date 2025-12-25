<?php

use App\Models\User;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

it('has correct primary key and uuid settings for User', function () {
    $user = new User;
    expect($user->getKeyName())->toBe('user_id')
        ->and($user->getIncrementing())->toBeFalse()
        ->and($user->getKeyType())->toBe('string');
});

it('has expected fillable attributes for User', function () {
    $user = new User;
    expect($user->getFillable())->toContain('name', 'email', 'password', 'phone_number', 'address', 'date_of_birth');
});

it('has roles relationship', function () {
    $user = new User;
    expect($user->roles())->toBeInstanceOf(BelongsToMany::class);
});
