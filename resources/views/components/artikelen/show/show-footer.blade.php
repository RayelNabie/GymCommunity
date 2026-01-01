@props([
    'post',
    'canEdit' => false,
    'canDelete' => false
])

@if($canEdit || $canDelete)
    <footer {{ $attributes->merge(['class' => 'mt-20 pt-10 border-t border-zinc-800 flex flex-wrap items-center justify-end gap-4']) }}>

        @if($canEdit)
            <a href="{{ route('artikelen.edit', $post) }}"
               class="btn btn-ghost border-zinc-800 text-zinc-400 hover:text-white hover:bg-zinc-800 transition-all group">
                <i data-lucide="edit-3" class="size-4 mr-2 group-hover:text-gym-primary transition-colors"></i>
                Artikel Bewerken
            </a>
        @endif

        @if($canDelete)
            <x-shared.delete-popup :action="route('artikelen.destroy', $post)"/>
        @endif

    </footer>
@endif
