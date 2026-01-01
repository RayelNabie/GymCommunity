@props(['post' => null])

@php
    $isEdit = $post?->exists;
    $action = $isEdit ? route('artikelen.update', $post) : route('artikelen.store');
@endphp

<form action="{{ $action }}"
      method="POST"
      enctype="multipart/form-data">

    @csrf
    @if($isEdit)
        @method('PUT')
    @endif

    {{-- form fields --}}
    <x-artikelen.shared.form-fields :post="$post"/>

    {{-- action buttons --}}
    <div class="flex items-center justify-end gap-4 pt-6 border-t border-zinc-800">
        <a href="{{ route('artikelen.index') }}"
           class="btn btn-ghost text-gym-secondary hover:bg-gym-primary hover:text-gym-background">
            Annuleren
        </a>

        <button type="submit" class="btn btn-primary px-4 hover:bg-gym-primary hover:text-gym-background">
            <i data-lucide="{{ $isEdit ? 'save' : 'send' }}" class="size-5 mr-2"></i>
            {{ $isEdit ? 'Wijzigingen Opslaan' : 'Publiceren' }}
        </button>
    </div>

</form>
