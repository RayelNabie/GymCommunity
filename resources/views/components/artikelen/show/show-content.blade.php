@props(['post'])

<div {{ $attributes->merge(['class' => 'space-y-12']) }}>
    @if($post->image)
        <figure class="rounded-3xl overflow-hidden shadow-2xl shadow-gym-primary/5 border border-zinc-800">
            <img src="{{ asset("storage/{$post->image}") }}"
                 alt="{{ $post->title }}"
                 class="w-full h-auto max-h-[600px] object-cover hover:scale-[1.01] transition-transform duration-700">
        </figure>
    @endif

        <div class="prose prose-invert prose-gym max-w-none text-zinc-300 leading-relaxed text-lg lg:text-xl whitespace-pre-line">
            {{ $post->body }}
        </div>
</div>
