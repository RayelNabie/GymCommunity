@props(['post'])

<header {{ $attributes->merge(['class' => 'relative mb-12']) }}>
    <h1 class="text-4xl md:text-6xl lg:text-7xl font-black text-white mb-8 leading-tight tracking-tighter uppercase italic">
        {{ $post->title }}
    </h1>

    <div
        class="grid grid-cols-2 lg:flex lg:items-center gap-6 text-gym-secondary border-y border-gym-surface py-8 backdrop-blur-sm bg-white/[0.02] px-4 rounded-sm">

        {{-- Username --}}
        <div class="flex items-center gap-3 group">
            <div
                class="size-11 rounded-full bg-gym-primary/10 flex items-center justify-center border border-gym-primary/20 transition-colors group-hover:bg-gym-primary/20">
                <i data-lucide="user" class="size-5 text-gym-primary"></i>
            </div>
            <div class="flex flex-col">
                <span class="text-[10px] uppercase tracking-widest text-zinc-500 font-bold">Auteur</span>
                <span class="font-bold text-white text-sm sm:text-base leading-none">{{ $post->user->name }}</span>
            </div>
        </div>

        {{-- Date --}}
        <div class="flex items-center gap-3">
            <div class="size-11 rounded-full bg-zinc-800/50 flex items-center justify-center border border-zinc-700">
                <i data-lucide="calendar" class="size-5 text-zinc-300"></i>
            </div>
            <div class="flex flex-col">
                <span class="text-[10px] uppercase tracking-widest text-zinc-500 font-bold">Gepubliceerd</span>
                <time datetime="{{ $post->created_at->toIso8601String() }}"
                      class="font-bold text-zinc-200 text-sm sm:text-base leading-none">
                    {{ $post->created_at->format('d M, Y') }}
                </time>
            </div>
        </div>

        {{-- Category --}}
        <div class="col-span-2 lg:col-span-1 lg:ml-auto flex justify-center lg:justify-end mt-2 lg:mt-0">
            <div
                class="px-6 py-2 rounded-lg border border-gym-primary/30 bg-gym-primary/5 text-gym-primary text-xs font-black uppercase tracking-[0.2em] italic shadow-[0_0_20px_rgba(250,204,21,0.05)]">
                {{ $post->category->label() }}
            </div>
        </div>
    </div>

</header>
