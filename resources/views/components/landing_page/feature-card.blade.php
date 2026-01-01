@props([
    'icon',
    'title',
    'description'
])

<article {{ $attributes->merge(['class' => 'card bg-zinc-800 shadow-xl border border-zinc-700 transition-all hover:border-gym-primary/50']) }}>
    <div class="card-body">
        <div class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-gym-primary">
            <i data-lucide="{{ $icon }}" class="w-6 h-6"></i>
        </div>
        <h3 class="card-title text-white">{{ $title }}</h3>
        <p class="text-gray-400">{{ $description }}</p>
    </div>
</article>
