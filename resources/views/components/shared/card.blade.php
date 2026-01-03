@props(['post', 'showActions' => false])

<article {{ $attributes->merge(['class' => 'card bg-zinc-900 border border-zinc-800 hover:border-gym-primary transition-all duration-300 group h-full flex flex-col']) }}>
    {{-- Afbeelding Section --}}
    <figure class="h-48 w-full overflow-hidden relative bg-zinc-800">
        @if($post->image)
            <img src="{{ asset("storage/{$post->image}") }}"
                 alt="{{ $post->title }}"
                 loading="lazy"
                 class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
            />
        @endif

        {{-- Fallback Icon --}}
        <div class="absolute inset-0 flex items-center justify-center pointer-events-none opacity-0 [.image-error_&]:opacity-100 {{ !$post->image ? 'opacity-100' : '' }}">
            <i data-lucide="image" class="w-12 h-12 text-zinc-600"></i>
        </div>

        <div class="absolute top-4 left-4 badge badge-primary font-bold shadow-lg">
            {{ $post->category->label() }}
        </div>
    </figure>

    <div class="card-body flex-grow p-6">
        <header class="flex items-center gap-3 text-sm text-gray-500 mb-3">
            <time datetime="{{ $post->created_at->toIso8601String() }}" class="flex items-center gap-1">
                <i data-lucide="calendar" class="w-4 h-4"></i>
                {{ $post->created_at->format('d M Y') }}
            </time>
            <span class="text-zinc-700">|</span>
            <address class="flex items-center gap-1 not-italic">
                <i data-lucide="user" class="w-4 h-4"></i>
                {{ $post->user->name }}
            </address>
        </header>

        <h2 class="card-title text-white text-xl mb-3 group-hover:text-gym-primary transition-colors line-clamp-2">
            {{ $post->title }}
        </h2>

        <p class="text-gray-400 line-clamp-3 mb-6 leading-relaxed">
            {{ str($post->body)->limit(150) }}
        </p>

        <div class="card-actions flex items-center justify-between mt-auto pt-4 border-t border-zinc-800/50">
            <div class="flex gap-1">
                @if($showActions)
                    <a href="{{ route('artikelen.edit', $post) }}"
                       class="btn btn-ghost btn-sm btn-square text-blue-400 hover:bg-blue-400/10"
                       title="Aanpassen">
                        <i data-lucide="pencil" class="w-4 h-4"></i>
                    </a>

                    <form action="{{ route('artikelen.destroy', $post) }}" method="POST"
                          onsubmit="return confirm('Weet je zeker dat je dit artikel wilt verwijderen?')">
                        @csrf
                        @method('DELETE')
                        <button type="submit" class="btn btn-ghost btn-sm btn-square text-error hover:bg-error/10" title="Verwijderen">
                            <i data-lucide="trash-2" class="w-4 h-4"></i>
                        </button>
                    </form>
                @endif
            </div>

            <a href="{{ route('artikelen.show', $post) }}"
               class="btn btn-ghost btn-sm text-gym-primary hover:bg-gym-primary/10 group/link">
                Lees meer
                <i data-lucide="arrow-right" class="w-4 h-4 transition-transform group-hover/link:translate-x-1"></i>
            </a>
        </div>
    </div>
</article>
