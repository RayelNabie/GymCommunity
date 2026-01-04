@can('update', $post)
    <div class="mt-8">

        {{-- User --}}
        @if(auth()->user()?->is($post->user))
            <p class="text-xs text-gym-text-light italic">
                Je kunt dit artikel beheren via 'Mijn Artikelen'.
            </p>
        @else

            {{-- De Admin/Moderator --}}
            <p class="text-xs text-gym-primary/80 italic">
                Je bekijkt dit artikel met beheerdersrechten. Aanpassingen kunnen via het admin-paneel.
            </p>
        @endif
    </div>
@endcan
