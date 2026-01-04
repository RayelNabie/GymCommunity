<x-app-layout :title="$post->title">
    <article class="max-w-4xl mx-auto py-12 px-4">
        <nav class="flex items-center justify-between mb-12">
            <a href="{{ route('artikelen.index') }}"
               class="btn btn-ghost btn-sm gap-2 text-zinc-500 hover:text-gym-primary transition-colors group">
                <i data-lucide="arrow-left" class="size-4 transition-transform group-hover:-translate-x-1"></i>
                Terug naar overzicht
            </a>
        </nav>

        <x-artikelen.show.show-header :$post/>

        <x-artikelen.show.show-content :$post/>

        <x-artikelen.show.show-footer :$post/>

    </article>
</x-app-layout>
