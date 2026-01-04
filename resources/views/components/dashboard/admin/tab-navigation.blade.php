@props(['activeTab', 'tabs' => []])

<div class="flex flex-wrap gap-2 p-1 bg-gym-surface border border-gym-border rounded-lg w-fit">
    @foreach($tabs as $key => $label)
        <a href="{{ route(Route::currentRouteName(), ['tab' => $key]) }}"
            @class([
                'px-4 py-2 rounded-md transition-all',
                'bg-gym-primary text-black font-bold' => $activeTab === $key,
                'text-gym-muted hover:text-white' => $activeTab !== $key
            ])>
            {{ $label }}
        </a>
    @endforeach
</div>
