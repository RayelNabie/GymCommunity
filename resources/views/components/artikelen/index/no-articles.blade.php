@props([
    'icon' => 'file-x',
    'title' => 'Geen gegevens gevonden',
    'description' => 'Het lijkt erop dat er op dit moment niets te tonen is.',
    'actionText' => null,
    'actionLink' => null,
])

<div {{ $attributes->merge(['class' => 'flex flex-col items-center justify-center py-20 px-6 text-center bg-zinc-900/50 rounded-2xl border-2 border-dashed border-zinc-800']) }}>
    {{-- Icon --}}
    <div class="relative mb-6">
        <div class="absolute inset-0 bg-gym-primary/20 blur-2xl rounded-full"></div>
        <div class="relative bg-zinc-800 size-20 rounded-full flex items-center justify-center border border-zinc-700 shadow-xl">
            <i data-lucide="{{ $icon }}" class="size-10 text-gym-primary"></i>
        </div>
    </div>

    {{-- Text Content --}}
    <h3 class="text-2xl font-bold text-white mb-2 tracking-tight">{{ $title }}</h3>
    <p class="text-gray-400 max-w-sm mx-auto leading-relaxed mb-8">
        {{ $description }}
    </p>

    {{-- Optional Action Button) --}}
    @if($actionText && $actionLink)
        <a href="{{ $actionLink }}" class="btn btn-primary font-black shadow-lg shadow-gym-primary/20">
            <i data-lucide="plus" class="size-5 mr-2"></i>
            {{ $actionText }}
        </a>
    @endif
</div>
