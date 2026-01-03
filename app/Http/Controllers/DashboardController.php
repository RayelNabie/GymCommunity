<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\View\View;

class DashboardController extends Controller
{
    /**
     *  Display a listing of the resource. Filtered by only the userid of the requester
     */
    public function index(): View
    {
        $posts = Post::query()
            ->with('user')
            ->myarticle(true)
            ->latest()
            ->paginate(10);

        return view('dashboard.user.index', [
            'posts' => $posts,
        ]);
    }
}
