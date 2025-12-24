<?php

use App\Models\Permission;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

it('has correct primary key and uuid settings for Permission', function () {
    $permission = new Permission;
    expect($permission->getKeyName())->toBe('permission_id')
        ->and($permission->getIncrementing())->toBeFalse()
        ->and($permission->getKeyType())->toBe('string');
});

it('has expected fillable attributes for Permission', function () {
    $permission = new Permission;
    expect($permission->getFillable())->toContain('name', 'description');
});

it('has roles relationship', function () {
    $permission = new Permission;
    expect($permission->roles())->toBeInstanceOf(BelongsToMany::class);
});
