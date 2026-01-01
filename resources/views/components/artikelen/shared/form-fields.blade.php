@use('App\Enums\PostCategoryEnum')
@props(['post' => null])

@php
    $selectedCategory = old('category', $post?->category?->value ?? $post?->category);
@endphp

{{-- Titel --}}
<div class="form-control w-full">
    <label for="title" class="label text-white font-medium">Titel</label>
    <input type="text"
           id="title"
           name="title"
           value="{{ old('title', $post?->title) }}"
           placeholder="Bijv. De voordelen van creatine"
           @class([
               'input input-bordered bg-gym-background border-gym-border focus:border-gym-primary w-full',
               'input-error' => $errors->has('title')
           ])
           required/>
    @error('title') <p class="mt-1 text-sm text-error">{{ $message }}</p> @enderror
</div>

{{-- Categorie --}}
<div class="form-control w-full mt-4">
    <label for="category" class="label text-white font-medium">Categorie</label>



    <select id="category"
            name="category"
            @class([
                'select select-bordered bg-gym-background border-gym-border w-full',
                'select-error' => $errors->has('category')
            ])
            required>
        <option disabled @selected(!$post) value="">Kies een categorie</option>

        @foreach(PostCategoryEnum::cases() as $categoryOption)
            <option value="{{ $categoryOption->value }}" @selected($selectedCategory === $categoryOption->value)>
                {{ $categoryOption->label() }}
            </option>
        @endforeach
    </select>

    @error('category')
    <p class="mt-1 text-sm text-error">{{ $message }}</p>
    @enderror
</div>

{{-- Afbeelding --}}
<div class="form-control w-full mt-4">
    <label for="image" class="label text-white font-medium block">
        Afbeelding <span
            class="text-xs opacity-50 ml-1">{{ $post ? '(Leeg laten om te behouden)' : '(Optioneel)' }}</span>
    </label>

    @if($post?->image)
        <div class="mb-3 w-32 shrink-0">
            <img src="{{ asset("storage/{$post->image}") }}"
                 class="h-20 w-32 rounded border border-gym-border object-cover shadow-md">
        </div>
    @endif

    <input type="file"
           id="image"
           name="image"
           accept="image/*"
        @class([
            'file-input file-input-bordered file-input-primary bg-gym-background w-full',
            'file-input-error' => $errors->has('image')
        ]) />
    @error('image') <p class="mt-1 text-sm text-error">{{ $message }}</p> @enderror
</div>

{{-- Inhoud --}}
<div class="form-control w-full mt-4">
    <label for="body" class="label text-white font-medium">Inhoud</label>
    <textarea id="body"
              name="body"
              placeholder="Schrijf hier je artikel..."
              @class([
                  'textarea textarea-bordered bg-gym-background border-gym-border h-64 w-full leading-relaxed',
                  'textarea-error' => $errors->has('body')
              ])
              required>{{ old('body', $post?->body) }}</textarea>
    @error('body') <p class="mt-1 text-sm text-error">{{ $message }}</p> @enderror
</div>
