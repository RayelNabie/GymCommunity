<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" data-theme="black">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Artikelen - {{ config('app.name', 'GymCommunity') }}</title>

    <!-- Fonts -->
    <link href="https://api.fontshare.com/v2/css?f[]=satoshi@300,400,500,700,900&display=swap" rel="stylesheet">

    <!-- DaisyUI & Tailwind CSS -->
    @vite(['resources/css/app.css', 'resources/js/app.js'])

    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>
</head>

<body class="flex flex-col min-h-screen bg-gym-background text-white">

<!-- Navbar -->
<x-shared.navbar/>

<main class="flex-grow container mx-auto px-4 py-12">
    <div class="flex flex-col md:flex-row justify-between items-end mb-12 gap-4">
        <div>
            <h1 class="text-4xl md:text-5xl font-bold text-white mb-4">
                Alle <span class="text-gym-primary">Artikelen</span>
            </h1>
            <p class="text-gym-muted text-lg max-w-2xl">
                Ontdek de laatste inzichten, trainingstips en wetenschappelijke analyses van onze community experts.
            </p>
        </div>
        <div class="flex gap-2"></div>
    </div>

    <!-- Posts -->
    @if($posts->count() > 0)
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            @foreach($posts as $post)
                <article
                    class="card bg-gym-surface shadow-xl border border-gym-border hover:border-gym-primary transition-all duration-300 group h-full flex flex-col">
                    @if($post->image)
                        <figure class="h-48 w-full overflow-hidden relative" x-data="{ imageError: false }">
                            <img x-show="!imageError"
                                 x-on:error="imageError = true"
                                 src="{{ asset('storage/' . $post->image) }}"
                                 alt="{{ $post->title }}"
                                 class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"/>

                            <div x-show="imageError"
                                 x-cloak
                                 class="w-full h-full bg-gym-surface-hover flex items-center justify-center absolute inset-0">
                                <i data-lucide="image-off" class="w-12 h-12 text-gym-icon"></i>
                            </div>

                            <div class="absolute top-4 left-4 badge badge-primary font-bold">
                                {{ $post->category->label() }}
                            </div>
                        </figure>
                    @else
                        <figure class="h-48 w-full bg-gym-surface-hover flex items-center justify-center relative">
                            <i data-lucide="image" class="w-12 h-12 text-gym-icon"></i>
                            <div class="absolute top-4 left-4 badge badge-primary font-bold">
                                {{ $post->category->label() }}
                            </div>
                        </figure>
                    @endif

                    <div class="card-body flex-grow">
                        <div class="flex items-center gap-2 text-sm text-gym-meta mb-2">
                            <div class="flex items-center gap-1">
                                <i data-lucide="calendar" class="w-4 h-4"></i>
                                <span>{{ $post->created_at->format('d M Y') }}</span>
                            </div>
                            <span>•</span>
                            <div class="flex items-center gap-1">
                                <i data-lucide="user" class="w-4 h-4"></i>
                                <span>{{ $post->user->name }}</span>
                            </div>
                        </div>

                        <h2 class="card-title text-white text-xl mb-2 group-hover:text-gym-primary transition-colors">
                            {{ $post->title }}
                        </h2>

                        <p class="text-gym-muted line-clamp-3 mb-4">
                            {{ \Illuminate\Support\Str::limit($post->body, 150) }}
                        </p>

                        <div class="card-actions justify-end mt-auto">
                            <a href="#"
                               class="btn btn-link text-gym-primary p-0 no-underline hover:underline flex items-center gap-1">
                                Lees meer <i data-lucide="arrow-right" class="w-4 h-4"></i>
                            </a>
                        </div>
                    </div>
                </article>
            @endforeach
        </div>
    @else
        <div class="text-center py-20 bg-gym-surface rounded-xl border border-gym-border">
            <div class="bg-gym-surface-hover w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <i data-lucide="file-x" class="w-8 h-8 text-gym-meta"></i>
            </div>
            <h3 class="text-xl font-bold text-white mb-2">Geen posts gevonden</h3>
            <p class="text-gym-muted">Er zijn nog geen posts geplaatst</p>
        </div>
    @endif
</main>

<!-- Footer -->
<x-shared.footer/>

<script>
    // Initialize Lucide Icons
    lucide.createIcons();
</script>
</body>

</html>
