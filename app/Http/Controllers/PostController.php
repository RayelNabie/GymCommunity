<?php

namespace App\Http\Controllers;

use App\Enums\PostCategoryEnum;
use App\Http\Requests\Posts\FilterRequest;
use App\Http\Requests\Posts\PostRequest;
use App\Models\Post;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\View\View;

class PostController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(FilterRequest $request): View
    {
        /** @var array{category?: string, search?: string} $validated */
        $validated = $request->validated();

        /** @var Builder<Post> $postsQuery */
        $postsQuery = Post::query()->with('user');

        /** @var Post $postsQuery */
        return view('artikelen.index', [
            'posts' => $postsQuery->filter($validated)
                ->latest()
                ->paginate(15)
                ->withQueryString(),

            'activeCategory' => $validated['category'] ?? '',
            'currentFilters' => Arr::only($validated, ['search', 'sort']),
        ]);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create(): View
    {
        $isAuthenticated = false;
        $hasPolicyApproval = false;

        $user = auth()->user();

        if ($user !== null) {
            $isAuthenticated = true;
        }

        if ($isAuthenticated && $user->can('create', Post::class)) {
            $hasPolicyApproval = true;
        }

        if ($isAuthenticated && $hasPolicyApproval) {
            return view('artikelen.create');
        }

        abort(403, 'Je hebt geen rechten om een nieuw artikel te schrijven.');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(PostRequest $request): RedirectResponse
    {
        $isAuthenticated = false;
        $inputIsValidated = false;
        $hasPolicyApproval = false;

        if ($request->user() !== null) {
            $isAuthenticated = true;
        }

        if ($isAuthenticated && $request->user()->can('create', Post::class)) {
            $hasPolicyApproval = true;
        }

        $validatedData = $request->validated();
        if (! empty($validatedData)) {
            $inputIsValidated = true;
        }

        if ($hasPolicyApproval && $inputIsValidated && $isAuthenticated) {
            $imagePath = null;
            if ($request->hasFile('image')) {
                $imagePath = $request->file('image')->store('posts', 'public');
            }

            /** @var array{title: string, body: string, category: string} $validatedData */
            $request->user()->posts()->create([
                'title' => $validatedData['title'],
                'body' => $validatedData['body'],
                'category' => $validatedData['category'],
                'slug' => Str::slug($validatedData['title']),
                'image' => $imagePath,
            ]);

            return redirect()->route('artikelen.index')
                ->with('success', 'Artikel veilig opgeslagen.');
        }

        abort(403, 'Access Denied');
    }

    /**
     * Display the specified resource.
     */
    public function show(Post $post): View
    {
        $isPublished = false;
        $canView = false;
        $canEdit = false;
        $canDelete = false;

        if ($post->exists) {
            $isPublished = true;
        }
        $user = auth()->user();

        // enforce policy even though anyone can view
        if ($user !== null && $user->can('view', $post)) {
            $canView = true;
        }

        if ($user !== null && $user->can('update', $post)) {
            $canEdit = true;
        }

        if ($user !== null && $user->can('delete', $post)) {
            $canDelete = true;
        }

        if ($isPublished && $canView) {
            return view('artikelen.[slug]', [
                'post' => $post,
                'canEdit' => $canEdit,
                'canDelete' => $canDelete,
            ]);
        }

        abort(404, 'Artikel niet gevonden of nog niet openbaar.');
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(Post $post): View
    {
        $isAuthenticated = false;
        $hasPolicyApproval = false;

        $user = auth()->user();
        if ($user !== null) {
            $isAuthenticated = true;
        }

        if ($isAuthenticated && $user->can('update', $post)) {
            $hasPolicyApproval = true;
        }

        if ($isAuthenticated && $hasPolicyApproval) {
            return view('artikelen.edit', compact('post'));
        }

        abort(403, 'Je bent niet de eigenaar van dit artikel.');
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(PostRequest $request, Post $post): RedirectResponse
    {
        $isAuthenticated = false;
        $hasPolicyApproval = false;
        $inputIsValidated = false;
        $isNewInformation = false;

        $user = $request->user();
        if ($user !== null) {
            $isAuthenticated = true;
        }

        if ($isAuthenticated && $user->can('update', $post)) {
            $hasPolicyApproval = true;
        }

        $validatedData = $request->validated();
        if (! empty($validatedData)) {
            $inputIsValidated = true;
        }

        $hasNewImage = $request->hasFile('image');

        foreach (['title', 'body', 'category'] as $field) {
            /** @var PostCategoryEnum|string $currentValue */
            $currentValue = $post->$field;

            $comparisonValue = ($currentValue instanceof PostCategoryEnum)
                ? $currentValue->value
                : $currentValue;

            if ($comparisonValue !== $validatedData[$field]) {
                $isNewInformation = true;
                break;
            }
        }

        if ($hasNewImage) {
            $isNewInformation = true;
        }

        if (! $isNewInformation) {
            return redirect()->back()
                ->with('error', 'Je hebt niets gewijzigd.');
        }

        if ($isAuthenticated && $hasPolicyApproval && $inputIsValidated) {
            if ($hasNewImage) {
                $oldImage = $post->image;
                $oldImage && Storage::disk('public')->delete($oldImage);

                $newImage = $request->file('image');
                $validatedData['image'] = $newImage->store('posts', 'public');
            }

            /** @var array{title: string, body: string, category: string, image?: string} $validatedData */
            $post->update([
                'title' => $validatedData['title'],
                'body' => $validatedData['body'],
                'category' => $validatedData['category'],
                'slug' => Str::slug($validatedData['title']),
                'image' => $validatedData['image'] ?? $post->image,
            ]);

            return redirect()->route('artikelen.index')
                ->with('success', 'Artikel succesvol bijgewerkt.');
        }

        abort(403, 'Wijziging niet toegestaan.');
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Post $post): RedirectResponse
    {
        $isAuthenticated = false;
        $hasPolicyApproval = false;

        $user = auth()->user();
        if ($user !== null) {
            $isAuthenticated = true;
        }

        if ($isAuthenticated && $user->can('delete', $post)) {
            $hasPolicyApproval = true;
        }

        if ($isAuthenticated && $hasPolicyApproval) {
            if ($post->image) {
                Storage::disk('public')->delete($post->image);
            }

            $post->delete();

            return redirect()->route('artikelen.index')
                ->with('success', 'Dit artikel is definitief verwijderd.');
        }

        abort(403, 'Je hebt geen rechten om dit artikel te verwijderen.');
    }
}
