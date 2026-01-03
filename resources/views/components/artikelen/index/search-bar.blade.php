<form action="{{ route('artikelen.index') }}" method="GET" class="w-full max-w-sm">
    <div class="join w-full shadow-lg shadow-gym-primary/10">

        {{-- Input Field --}}
        <input
            type="search"
            name="search"
            value="{{ request('search') }}"
            placeholder="Zoek op titel of inhoud..."
            class="input input-bordered join-item w-full bg-gym-surface text-white placeholder-gym-muted border-gym-muted/20 focus:outline-none focus:border-gym-primary focus:ring-1 focus:ring-gym-primary transition-all"
        />
        {{-- Search Button --}}
        <button type="submit"
                class="btn join-item bg-gym-primary text-black hover:bg-gym-accent border-none transition-colors px-2">
            <i data-lucide="search" class="size-5"></i>
        </button>
    </div>
</form>
