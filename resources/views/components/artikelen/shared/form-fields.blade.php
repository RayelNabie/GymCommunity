@use('App\Enums\PostCategoryEnum')
@use('App\Models\Post')

@props([
    /** @var Post|null */
    'post' => null
])

{{-- Title --}}
<div class="form-control w-full">
    <label for="title" class="label text-white font-medium">Titel</label>

    <input type="text"
           id="title"
           name="title"
           value="{{ old('title', $post?->title) }}"
           placeholder="Bijv. De voordelen van creatine"
           @class([
               'input input-bordered bg-gym-background border-gym-border focus:border-gym-primary focus:outline-none w-full',
               'input-error' => $errors->has('title')
           ])
           required/>

    @error('title')
    <p class="mt-1 text-sm text-error">{{ $message }}</p>
    @enderror
</div>

{{-- Category --}}
<div class="form-control w-full">
    <label for="category" class="label text-white font-medium">Categorie</label>

    <select id="category"
            name="category"
            @class([
                'select select-bordered bg-gym-background border-gym-border focus:border-gym-primary focus:outline-none w-full',
                'select-error' => $errors->has('category')
            ])
            required>
        <option disabled @selected(!$post) value="">Kies een categorie</option>

        @foreach(PostCategoryEnum::cases() as $category)
            <option value="{{ $category->value }}" @selected(old('category', $post?->category) === $category->value)>
                {{ $category->label() }}
            </option>
        @endforeach
    </select>
</div>

{{-- Image Input --}}
<div class="form-control w-full">
    <label for="image" class="label text-white font-medium">
        Afbeelding {{ $post ? '(Laat leeg om huidige te behouden)' : '(Optioneel)' }}
    </label>

    @if($post?->image)
        <div class="mb-3 group relative w-32">
            <img src="{{ asset("storage/{$post->image}") }}"
                 alt="{{ $post->title }}"
                 class="h-20 w-32 rounded border border-gym-border object-cover shadow-lg transition-opacity group-hover:opacity-75">
        </div>
    @endif

    <input type="file"
           id="image"
           name="image"
           @class([
               'file-input file-input-bordered file-input-primary bg-gym-background border-gym-border w-full transition-all',
               'file-input-error ring-1 ring-error' => $errors->has('image')
           ])
           accept="image/*"/>
</div>

{{-- Body --}}
<div class="form-control w-full">
    <label for="body" class="label text-white font-medium">Inhoud</label>

    <textarea id="body"
              name="body"
              placeholder="Schrijf hier je artikel..."
              @class([
                  'textarea textarea-bordered bg-gym-background border-gym-border focus:border-gym-primary focus:outline-none h-64 w-full',
                  'textarea-error' => $errors->has('body')
              ])
              required>{{ old('body', $post?->body) }}</textarea>
</div>
