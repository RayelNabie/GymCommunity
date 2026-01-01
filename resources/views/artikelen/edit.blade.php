<x-app-layout title="Artikel Bewerken">
    {{--Title --}}
    <div class="max-w-2xl mx-auto">
        <div class="mb-8">
            <a href="{{ route('artikelen.index') }}" class="btn btn-ghost btn-sm gap-2 text-gym-muted hover:text-white pl-0">
                <i data-lucide="arrow-left" class="w-4 h-4"></i> Terug
            </a>
            <h1 class="text-3xl font-bold text-white mt-4">Artikel <span class="text-gym-primary">Bewerken</span></h1>
        </div>

        {{-- Form --}}
        <div class="card bg-gym-surface border border-gym-border shadow-xl">
            <div class="card-body">
                <x-artikelen.shared.form :post="$post" />
            </div>
        </div>
    </div>
</x-app-layout>
