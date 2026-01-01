<?php

namespace App\Http\Controllers;

use App\Http\Requests\Posts\PostCreateRequest;
use App\Http\Requests\Posts\PostUpdateRequest;
use App\Models\Post;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\View\View;

class PostController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(): View
    {
        $posts = Post::with('user')->latest()->paginate(15);

        return view('artikelen.index', ['posts' => $posts]);
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
    public function store(PostCreateRequest $request): RedirectResponse
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
        if (!empty($validatedData)) {
            $inputIsValidated = true;
        }

        if ($hasPolicyApproval && $inputIsValidated && $isAuthenticated) {
            /** @var array{title: string, body: string, category: string} $validatedData */
            $request->user()->posts()->create([
                'title' => $validatedData['title'],
                'body' => $validatedData['body'],
                'category' => $validatedData['category'],
                'slug' => Str::slug($validatedData['title']),
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
        $isOwnerOrAdmin = false;

        if ($post->exists) {
            $isPublished = true;
        }
        $user = auth()->user();
        if ($user !== null && $user->can('view', $post)) {
            $isOwnerOrAdmin = true;
        }

        if ($isPublished || $isOwnerOrAdmin) {
            return view('artikelen.show', compact('post'));
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
    public function update(PostUpdateRequest $request, Post $post): RedirectResponse
    {
        $isAuthenticated = false;
        $hasPolicyApproval = false;
        $inputIsValidated = false;

        $user = $request->user();
        if ($user !== null) {
            $isAuthenticated = true;
        }

        if ($isAuthenticated && $user->can('update', $post)) {
            $hasPolicyApproval = true;
        }

        $validatedData = $request->validated();
        if (!empty($validatedData)) {
            $inputIsValidated = true;
        }

        if ($isAuthenticated && $hasPolicyApproval && $inputIsValidated) {
            if ($request->hasFile('image')) {
                $validatedData['image'] = $request->file('image')->store('posts', 'public');
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
                ->with('success', 'Artikel en bijbehorende media definitief verwijderd.');
        }

        abort(403, 'Je hebt geen rechten om dit artikel te verwijderen.');
    }
}
