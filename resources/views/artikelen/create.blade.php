<x-app-layout title="Nieuw Artikel Publiceren">
    <div class="py-12">
        {{-- Header van de pagina --}}
        <div class="mb-10">
            <h1 class="text-4xl font-black text-white tracking-tighter uppercase italic">
                Nieuw <span class="text-gym-primary">Artikel</span>
            </h1>
            <p class="text-zinc-400 mt-2">Deel je expertise en help de community groeien.</p>
        </div>

        {{-- Het Formulier --}}
        <div class="bg-zinc-900/50 border border-zinc-800 rounded-3xl p-8 backdrop-blur-md">
            <x-artikelen.shared.form />
        </div>
    </div>
</x-app-layout>
