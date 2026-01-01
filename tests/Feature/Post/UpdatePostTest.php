<?php

use App\Enums\PermissionEnum;
use App\Enums\PostCategoryEnum;
use App\Enums\RoleEnum;
use App\Models\Permission;
use App\Models\Post;
use App\Models\Role;
use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

describe('Happy Flow', function () {
    it('allows the owner to update their own post', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $updatedData = [
            'title' => 'Updated Title',
            'body' => str_repeat('This is the updated body content for the post. ', 5),
            'category' => PostCategoryEnum::VOEDING->value,
        ];

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), $updatedData);

        $response->assertRedirect(route('artikelen.index'));
        $response->assertSessionHas('success');

        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'title' => 'Updated Title',
            'category' => PostCategoryEnum::VOEDING->value,
        ]);
    });

    it('updates the slug when the title is updated', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $updatedData = [
            'title' => 'New Unique Title',
            'body' => $post->body,
            'category' => $post->category->value,
        ];

        $this->actingAs($user)->put(route('artikelen.update', $post), $updatedData);

        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'slug' => 'new-unique-title',
        ]);
    });

    it('allows a user with EDIT_ANY_POSTS permission to update another users post', function () {
        $owner = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id]);

        $admin = User::factory()->create();
        $permission = Permission::create([
            'name' => PermissionEnum::EDIT_ANY_POSTS,
            'description' => PermissionEnum::EDIT_ANY_POSTS->description(),
        ]);
        $role = Role::create([
            'name' => RoleEnum::ADMIN,
            'description' => RoleEnum::ADMIN->label(),
        ]);
        $role->permissions()->attach($permission);
        $admin->roles()->attach($role);

        $updatedData = [
            'title' => 'Admin Updated Title',
            'body' => $post->body,
            'category' => $post->category->value,
        ];

        $response = $this->actingAs($admin)->put(route('artikelen.update', $post), $updatedData);

        $response->assertRedirect(route('artikelen.index'));
        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'title' => 'Admin Updated Title',
        ]);
    });

    it('allows updating the post image', function () {
        Storage::fake('public');
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $file = UploadedFile::fake()->image('new_image.jpg');

        $updatedData = [
            'title' => $post->title,
            'body' => $post->body,
            'category' => $post->category->value,
            'image' => $file,
        ];

        $this->actingAs($user)->put(route('artikelen.update', $post), $updatedData);

        $post->refresh();
        expect($post->image)->not->toBeNull();
        Storage::disk('public')->assertExists($post->image);
    });

    it('keeps the old image if no new image is uploaded', function () {
        Storage::fake('public');
        $user = User::factory()->create();
        $oldImage = UploadedFile::fake()->image('old.jpg')->store('posts', 'public');
        $post = Post::factory()->create([
            'user_id' => $user->user_id,
            'image' => $oldImage,
        ]);

        $updatedData = [
            'title' => 'Updated Title',
            'body' => $post->body,
            'category' => $post->category->value,
        ];

        $this->actingAs($user)->put(route('artikelen.update', $post), $updatedData);

        $post->refresh();
        expect($post->image)->toBe($oldImage);
    });

    it('allows updating only the category', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create([
            'user_id' => $user->user_id,
            'category' => PostCategoryEnum::KRACHT,
        ]);

        $updatedData = [
            'title' => $post->title,
            'body' => $post->body,
            'category' => PostCategoryEnum::CARDIO->value,
        ];

        $this->actingAs($user)->put(route('artikelen.update', $post), $updatedData);

        $this->assertDatabaseHas('posts', [
            'post_id' => $post->post_id,
            'category' => PostCategoryEnum::CARDIO->value,
        ]);
    });

    it('returns an error when updating with the same data', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $sameData = [
            'title' => $post->title,
            'body' => $post->body,
            'category' => $post->category->value,
        ];

        $response = $this->actingAs($user)->from(route('artikelen.edit', $post))->put(route('artikelen.update', $post), $sameData);

        $response->assertRedirect(route('artikelen.edit', $post));
        $response->assertSessionHas('error', 'Je hebt niets gewijzigd.');
    });
});

describe('Unhappy Flow', function () {
    it('redirects guests to login page when trying to update', function () {
        $post = Post::factory()->create();

        $response = $this->put(route('artikelen.update', $post), [
            'title' => 'Hacked Title',
        ]);

        $response->assertRedirect('/login');
    });

    it('returns 403 when a user tries to update another users post without permission', function () {
        $owner = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $owner->user_id]);

        $otherUser = User::factory()->create();

        $response = $this->actingAs($otherUser)->put(route('artikelen.update', $post), [
            'title' => 'Malicious Update',
            'body' => $post->body,
            'category' => $post->category->value,
        ]);

        $response->assertStatus(403);
    });

    it('requires a title', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => '',
            'body' => $post->body,
            'category' => $post->category->value,
        ]);

        $response->assertSessionHasErrors('title');
    });

    it('requires a title of at least 5 characters', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => '1234',
            'body' => $post->body,
            'category' => $post->category->value,
        ]);

        $response->assertSessionHasErrors('title');
    });

    it('does not allow HTML in the title', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => '<b>Bold Title</b>',
            'body' => $post->body,
            'category' => $post->category->value,
        ]);

        $response->assertSessionHasErrors('title');
    });

    it('requires a body', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => $post->title,
            'body' => '',
            'category' => $post->category->value,
        ]);

        $response->assertSessionHasErrors('body');
    });

    it('requires a body of at least 50 characters', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => $post->title,
            'body' => 'Too short',
            'category' => $post->category->value,
        ]);

        $response->assertSessionHasErrors('body');
    });

    it('does not allow HTML in the body', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => $post->title,
            'body' => str_repeat('Valid text ', 10).'<script>alert("xss")</script>',
            'category' => $post->category->value,
        ]);

        $response->assertSessionHasErrors('body');
    });

    it('requires a category', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => $post->title,
            'body' => $post->body,
            'category' => '',
        ]);

        $response->assertSessionHasErrors('category');
    });

    it('requires a valid category enum value', function () {
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => $post->title,
            'body' => $post->body,
            'category' => 'invalid-category',
        ]);

        $response->assertSessionHasErrors('category');
    });

    it('validates the image file type', function () {
        Storage::fake('public');
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        $file = UploadedFile::fake()->create('document.pdf', 100);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => $post->title,
            'body' => $post->body,
            'category' => $post->category->value,
            'image' => $file,
        ]);

        $response->assertSessionHasErrors('image');
    });

    it('validates the image size', function () {
        Storage::fake('public');
        $user = User::factory()->create();
        $post = Post::factory()->create(['user_id' => $user->user_id]);

        // 3MB file (limit is 2048KB)
        $file = UploadedFile::fake()->image('large_image.jpg')->size(3000);

        $response = $this->actingAs($user)->put(route('artikelen.update', $post), [
            'title' => $post->title,
            'body' => $post->body,
            'category' => $post->category->value,
            'image' => $file,
        ]);

        $response->assertSessionHasErrors('image');
    });
});
