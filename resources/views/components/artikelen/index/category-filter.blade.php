@use('App\Enums\PostCategoryEnum')

@props([
    'activeCategory' => '',
    'currentFilters' => []
])

@php
    $isAllActive = empty($activeCategory);

    // Styling
    $sharedStyles = 'btn btn-sm rounded-full px-6 font-bold transition-all border-none';
    $highlightStyles = 'bg-gym-primary text-black hover:bg-gym-accent shadow-lg shadow-gym-primary/20';
    $ghostStyles = 'btn-ghost hover:bg-gym-surface-hover text-gym-muted hover:text-white';
@endphp

<div class="flex flex-wrap gap-2">
    {{-- All Button --}}
    <a href="{{ route('artikelen.index', Arr::except($currentFilters, 'category')) }}"
        @class([
            $sharedStyles,
            $highlightStyles => $isAllActive,
            $ghostStyles => !$isAllActive
        ])>
        Alles
    </a>

    {{-- Categories Button --}}
    @foreach(PostCategoryEnum::cases() as $category)
        @php
            $isActive = ($activeCategory === $category->value);
            $url = route('artikelen.index', array_merge($currentFilters, ['category' => $category->value]));
        @endphp

        <a href="{{ $url }}"
            @class([
                $sharedStyles,
                $highlightStyles => $isActive,
                $ghostStyles => !$isActive
            ])>
            {{ $category->label() }}
        </a>
    @endforeach
</div>
