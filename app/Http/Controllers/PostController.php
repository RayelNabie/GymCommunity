<?php

namespace App\Http\Controllers;

use App\Enums\PostCategoryEnum;
use App\Http\Requests\Posts\FilterRequest;
use App\Http\Requests\Posts\PostRequest;
use App\Models\Post;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
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

        /** @phpstan-ignore-next-line Reason: Larastan cannot resolve #[Scope] methods (category, search) on the Builder instance. */
        $posts = Post::query()
            ->active()
            ->with('user')
            ->category($validated['category'] ?? null)
            ->search($validated['search'] ?? null)
            ->latest()
            ->paginate(15)
            ->withQueryString();

        return view('artikelen.index', [
            'posts' => $posts,
            'activeCategory' => $validated['category'] ?? '',
            'currentFilters' => $validated,
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
        $user = auth()->user();

        if (! $post->is_active) {
            if (! $user || ! $user->can('update', $post)) {
                abort(404, 'Artikel niet gevonden of nog niet openbaar.');
            }
        }

        return view('artikelen.[slug]', [
            'post' => $post,
            'canEdit' => $user && $user->can('update', $post),
            'canDelete' => $user && $user->can('delete', $post),
        ]);
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

            return redirect()->route('dashboard')
                ->with('success', 'Dit artikel is definitief verwijderd.');
        }

        abort(403, 'Je hebt geen rechten om dit artikel te verwijderen.');
    }

    /**
     * Toggle the active status of the post.
     */
    public function toggleActive(Request $request, Post $post): RedirectResponse
    {
        if (! $request->user() || ! $request->user()->can('update', $post)) {
            abort(403, 'Je hebt geen rechten om de status van dit artikel te wijzigen.');
        }

        $post->update([
            'is_active' => ! $post->is_active,
        ]);

        return back()->with('success', 'Artikel status bijgewerkt.');
    }
}
