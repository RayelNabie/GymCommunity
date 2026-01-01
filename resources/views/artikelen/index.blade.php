@use('App\Models\Post')

<x-app-layout title="Artikelen">
    {{-- Header --}}
    <header class="flex flex-col md:flex-row justify-between items-end mb-16 gap-6">
        <div class="space-y-4">
            <h1 class="text-5xl md:text-6xl font-black text-white tracking-tighter uppercase italic">
                Alle <span class="text-gym-primary">Artikelen</span>
            </h1>
            <p class="text-gray-400 text-lg max-w-2xl leading-relaxed">
                Ontdek de laatste inzichten, trainingstips en wetenschappelijke analyses van onze community experts.
            </p>
        </div>

        @can('create', Post::class)
            <a href="{{ route('artikelen.create') }}"
               class="btn btn-primary btn-lg shadow-lg shadow-gym-primary/20 font-black transition-all hover:scale-105 active:scale-95">
                <i data-lucide="plus" class="size-5"></i>
                Nieuw Artikel
            </a>
        @endcan
    </header>

    {{-- Articles --}}
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-10">
        @forelse($posts as $post)
            <x-artikelen.index.card :$post />
        @empty
            <div class="col-span-full">
                <x-artikelen.index.no-articles
                    icon="clipboard-list"
                    title="Nog geen artikelen"
                    description="De community is nog even aan het opwarmen. Wees de eerste die zijn kennis deelt over krachttraining of voeding!"
                    action-text="Schrijf eerste artikel"
                    :action-link="route('artikelen.create')"
                />
            </div>
        @endforelse
    </div>

    {{-- Pagination --}}
    @if($posts->hasPages())
        <nav class="mt-20 py-8 border-t border-zinc-800/50">
            {{ $posts->links() }}
        </nav>
    @endif
</x-app-layout>
