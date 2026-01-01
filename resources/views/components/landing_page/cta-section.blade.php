@props([
    'title' => 'Klaar om de diepte in te gaan?',
    'description' => 'Word onderdeel van de grootste community-gedreven denktank en til je training naar een wetenschappelijk niveau.',
    'buttonText' => 'Meld je gratis aan',
    'buttonLink' => route('register')
])

<section {{ $attributes->merge(['class' => 'py-32 bg-gym-primary text-black relative overflow-hidden']) }}>
    {{-- Moderne decoratieve cirkels met Tailwind 4/Laravel 12 focus --}}
    <div class="absolute top-0 left-0 -ml-20 -mt-20 size-64 rounded-full bg-black opacity-10 blur-3xl"></div>
    <div class="absolute bottom-0 right-0 -mr-20 -mb-20 size-80 rounded-full bg-white opacity-20 blur-2xl"></div>

    <div class="container mx-auto px-4 text-center relative z-10">
        <h2 class="text-3xl lg:text-5xl font-bold mb-6 tracking-tight">
            {{ $title }}
        </h2>

        <p class="text-xl text-zinc-800 mb-10 max-w-2xl mx-auto leading-relaxed">
            {{ $description }}
        </p>

        <a href="{{ $buttonLink }}"
           class="btn btn-lg bg-black text-gym-primary hover:bg-zinc-900 border-none px-10 font-black uppercase tracking-widest shadow-2xl transition-all hover:scale-105">
            {{ $buttonText }}
        </a>
    </div>
</section>
