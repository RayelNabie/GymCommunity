<?php

namespace App\Http\Controllers;

use App\Http\Requests\Posts\PostCreateRequest;
use App\Models\Post;
use Illuminate\Http\RedirectResponse;
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

        return view('artikelen.index', [
            'posts' => $posts,
        ]);
    }

    //    /**
    //     * Show the form for creating a new resource.
    //     */
    //    public function create(Request $request)
    //    {
    //        //
    //    }

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
        if (! empty($validatedData)) {
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

    //    /**
    //     * Display the specified resource.
    //     */
    //    public function show(string $id)
    //    {
    //        //
    //    }
    //
    //    /**
    //     * Show the form for editing the specified resource.
    //     */
    //    public function edit(string $id)
    //    {
    //        //
    //    }
    //
    //    /**
    //     * Update the specified resource in storage.
    //     */
    //    public function update(Request $request, string $id)
    //    {
    //        //
    //    }
    //
    //    /**
    //     * Remove the specified resource from storage.
    //     */
    //    public function destroy(string $id)
    //    {
    //        //
    //    }
}
