<?php

use App\Models\Role;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

it('has correct primary key and uuid settings for Role', function () {
    $role = new Role;
    expect($role->getKeyName())->toBe('role_id')
        ->and($role->getIncrementing())->toBeFalse()
        ->and($role->getKeyType())->toBe('string');
});

it('has expected fillable attributes for Role', function () {
    $role = new Role;
    expect($role->getFillable())->toContain('name', 'description');
});

it('has users relationship', function () {
    $role = new Role;
    expect($role->users())->toBeInstanceOf(BelongsToMany::class);
});
