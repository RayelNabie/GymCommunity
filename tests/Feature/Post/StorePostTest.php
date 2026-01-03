<?php

use App\Enums\PermissionEnum;
use App\Enums\PostCategoryEnum;
use App\Enums\RoleEnum;
use App\Models\Permission;
use App\Models\Post;
use App\Models\Role;
use App\Models\User;
use Illuminate\Support\Str;

describe('Happy Flow', function () {
    it('can create an article', function () {
        $user = User::factory()->create();

        $permission = Permission::create([
            'name' => PermissionEnum::CREATE_POSTS,
            'description' => PermissionEnum::CREATE_POSTS->description(),
        ]);

        $role = Role::create([
            'name' => RoleEnum::TRAINER,
            'description' => RoleEnum::TRAINER->label(),
        ]);

        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $payload = [
            'title' => 'De Toekomst van Laravel in 2025',
            'body' => 'Dit is een uitgebreid artikel over de nieuwste technieken binnen het framework...',
            'category' => PostCategoryEnum::KRACHT->value,
        ];

        $response = $this->actingAs($user)->post(route('artikelen.store'), $payload);

        $response->assertRedirect(route('artikelen.index'));
        $response->assertSessionHas('success');

        $this->assertDatabaseHas('posts', [
            'title' => 'De Toekomst van Laravel in 2025',
        ]);

        $post = Post::where('title', 'De Toekomst van Laravel in 2025')->first();
        expect(Str::isUuid($post->post_id))->toBeTrue();
    });

    it('redirects correctly to index with query parameters preserved', function () {
        $user = User::factory()->create();

        $permission = Permission::create([
            'name' => PermissionEnum::CREATE_POSTS,
            'description' => PermissionEnum::CREATE_POSTS->description(),
        ]);

        $role = Role::create([
            'name' => RoleEnum::TRAINER,
            'description' => RoleEnum::TRAINER->label(),
        ]);

        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $payload = [
            'title' => 'Test Article with Filters',
            'body' => 'Dit is een test artikel om filters te controleren...',
            'category' => PostCategoryEnum::KRACHT->value,
        ];

        $response = $this->actingAs($user)->post(route('artikelen.store'), $payload);

        $response->assertRedirect(route('artikelen.index'));
        $response->assertSessionHas('success');

        // Verify the post was created
        $this->assertDatabaseHas('posts', [
            'title' => 'Test Article with Filters',
        ]);
    });
});

describe('Unhappy Flow', function () {
    it('redirects a guest to the login page', function () {
        $response = $this->post(route('artikelen.store'), ['title' => 'Hack poging']);

        $response->assertRedirect('/login');
    });

    it('returns 403 when user lacks the correct permission', function () {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->post(route('artikelen.store'), [
            'title' => 'Geen Rechten',
            'body' => str_repeat('Lange body tekst...', 10),
            'category' => PostCategoryEnum::KRACHT->value,
        ]);

        $response->assertStatus(403);
    });

    it('rejects input containing XSS injection', function () {
        $user = User::factory()->create();

        $permission = Permission::create([
            'name' => PermissionEnum::CREATE_POSTS,
            'description' => PermissionEnum::CREATE_POSTS->description(),
        ]);

        $role = Role::create([
            'name' => RoleEnum::TRAINER,
            'description' => RoleEnum::TRAINER->label(),
        ]);

        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $response = $this->actingAs($user)->post(route('artikelen.store'), [
            'title' => 'Titel with <script>alert(1)</script>',
            'body' => str_repeat('Body with <script>alert(1)</script>', 10),
            'category' => 'Injected Category with <script>alert(1)</script>',
        ]);

        $response->assertSessionHasErrors(['title']);
    });

    it('validates that the category must be a valid Enum value', function () {
        $user = User::factory()->create();
        $permission = Permission::create([
            'name' => PermissionEnum::CREATE_POSTS,
            'description' => PermissionEnum::CREATE_POSTS->description(),
        ]);

        $role = Role::create([
            'name' => RoleEnum::TRAINER,
            'description' => RoleEnum::TRAINER->label(),
        ]);

        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $response = $this->actingAs($user)->post(route('artikelen.store'), [
            'title' => 'Geldige Titel',
            'body' => str_repeat('Lange body tekst...', 10),
            'category' => 'invalid-category',
        ]);

        $response->assertSessionHasErrors(['category']);
    });
    it('treats complex SQL injection payloads as plain text', function (string $payload) {
        $user = User::factory()->create();
        $permission = Permission::create(['name' => PermissionEnum::CREATE_POSTS]);
        $role = Role::create(['name' => RoleEnum::TRAINER]);
        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $response = $this->actingAs($user)->post(route('artikelen.store'), [
            'title' => $payload,
            'body' => str_repeat('Valid body text ', 10),
            'category' => PostCategoryEnum::KRACHT->value,
        ]);

        $response->assertRedirect(route('artikelen.index'));
        $this->assertDatabaseHas('posts', [
            'title' => $payload,
        ]);
    })->with([
        ["'; DROP TABLE posts; --"],
        ["' OR 1=1; --"],
        ["admin' --"],
        ["' UNION ALL SELECT NULL, NULL, NULL --"],
        ["'; EXEC xp_cmdshell('dir'); --"],
        ["' OR '1'='1"],
    ]);

    it('treats Command injection payloads as plain text', function () {
        $user = User::factory()->create();
        $permission = Permission::create(['name' => PermissionEnum::CREATE_POSTS]);
        $role = Role::create(['name' => RoleEnum::TRAINER]);
        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $payload = '; rm -rf /';

        $response = $this->actingAs($user)->post(route('artikelen.store'), [
            'title' => $payload,
            'body' => str_repeat('Valid body text ', 10),
            'category' => PostCategoryEnum::KRACHT->value,
        ]);

        $response->assertRedirect(route('artikelen.index'));
        $this->assertDatabaseHas('posts', [
            'title' => $payload,
        ]);
    });

    it('treats SSTI (Server Side Template Injection) payloads as plain text', function () {
        $user = User::factory()->create();
        $permission = Permission::create(['name' => PermissionEnum::CREATE_POSTS]);
        $role = Role::create(['name' => RoleEnum::TRAINER]);
        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $payload = '{{ 7*7 }}';

        $response = $this->actingAs($user)->post(route('artikelen.store'), [
            'title' => $payload,
            'body' => str_repeat('Valid body text ', 10),
            'category' => PostCategoryEnum::KRACHT->value,
        ]);

        $response->assertRedirect(route('artikelen.index'));
        $this->assertDatabaseHas('posts', [
            'title' => $payload,
        ]);
    });

    it('treats LDAP/XPath injection payloads as plain text', function () {
        $user = User::factory()->create();
        $permission = Permission::create(['name' => PermissionEnum::CREATE_POSTS]);
        $role = Role::create(['name' => RoleEnum::TRAINER]);
        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $payload = 'admin*)(|(password=*))';

        $response = $this->actingAs($user)->post(route('artikelen.store'), [
            'title' => $payload,
            'body' => str_repeat('Valid body text ', 10),
            'category' => PostCategoryEnum::KRACHT->value,
        ]);

        $response->assertRedirect(route('artikelen.index'));
        $this->assertDatabaseHas('posts', [
            'title' => $payload,
        ]);
    });
});
