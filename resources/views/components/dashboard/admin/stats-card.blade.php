@props(['title', 'value', 'icon' => null, 'valueClass' => ''])

<div class="stats shadow bg-gym-surface border border-gym-border text-white">
    <div class="stat">
        @if($icon)
            <div class="stat-figure text-gym-primary">
                <i data-lucide="{{ $icon }}" class="w-8 h-8"></i>
            </div>
        @endif

        <div class="stat-title text-gym-muted">{{ $title }}</div>
        <div class="stat-value text-gym-primary {{ $valueClass }}">
            {{ $value }}
        </div>
    </div>
</div>
