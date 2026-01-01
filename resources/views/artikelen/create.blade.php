<x-app-layout title="Nieuw Artikel">
    <div class="max-w-2xl mx-auto">
        <div class="mb-8">
            <a href="{{ route('artikelen.index') }}" class="btn btn-ghost btn-sm gap-2 text-gym-muted hover:text-white pl-0">
                <i data-lucide="arrow-left" class="w-4 h-4"></i>
                Terug naar overzicht
            </a>
            <h1 class="text-3xl md:text-4xl font-bold text-white mt-4">
                Nieuw <span class="text-gym-primary">Artikel</span>
            </h1>
            <p class="text-gym-muted mt-2">
                Deel jouw kennis en ervaring met de community.
            </p>
        </div>

        <div class="card bg-gym-surface border border-gym-border shadow-xl">
            <div class="card-body">
                <form action="{{ route('artikelen.store') }}" method="POST" enctype="multipart/form-data" class="flex flex-col gap-6">
                    @csrf

                    <x-artikelen.shared.form-fields />

                    <div class="card-actions justify-end mt-4">
                        <button type="submit" class="btn bg-gym-primary text-gym-background hover:bg-gym-accent font-bold w-full md:w-auto">
                            <i data-lucide="send" class="w-4 h-4 mr-2"></i>
                            Publiceren
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</x-app-layout>
