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
            <form action="{{ route('artikelen.store') }}"
                  method="POST"
                  enctype="multipart/form-data"
                  class="space-y-6">

                @csrf
                <x-artikelen.shared.form-fields />

                {{-- Actie Knoppen --}}
                <div class="flex items-center justify-end gap-4 pt-6 border-t border-zinc-800">
                    <a href="{{ route('artikelen.index') }}" class="btn btn-ghost text-gym-secondary hover:bg-gym-primary hover:text-gym-background">
                        Annuleren
                    </a>

                    <button type="submit" class="btn btn-primary px-4 hover:bg-gym-primary hover:text-gym-background">
                        <i data-lucide="send" class="size-5 mr-2"></i>
                        Publiceren
                    </button>
                </div>
            </form>
        </div>
    </div>
</x-app-layout>
