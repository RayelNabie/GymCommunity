@props(['item', 'route', 'tooltipPosition' => 'top'])

<form action="{{ route($route, $item) }}" method="POST" {{ $attributes->merge(['class' => 'inline-flex items-center']) }}>
    @csrf
    @method('PATCH')
    <div class="tooltip tooltip-{{ $tooltipPosition }}" data-tip="{{ $item->is_active ? 'Deactiveren' : 'Activeren' }}">
        <input type="checkbox"
               class="toggle toggle-sm shrink-0 border-gym-icon bg-gym-background [--tglbg:theme(colors.gym.muted)] checked:bg-gym-primary checked:border-gym-primary checked:[--tglbg:theme(colors.gym.background)] hover:bg-gym-surface-hover hover:border-gym-text-light transition-all"
               onchange="this.form.submit()"
               {{ $item->is_active ? 'checked' : '' }} />
    </div>
</form>
