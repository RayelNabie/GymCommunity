<x-app-layout title="Nieuw Artikel">
    <div class="max-w-2xl mx-auto">
        <div class="mb-8">
            <a href="{{ route('artikelen.index') }}" class="btn btn-ghost btn-sm gap-2 text-gym-muted hover:text-white pl-0">
                <i data-lucide="arrow-left" class="w-4 h-4"></i>
                Terug naar overzicht
            </a>
            <h1 class="text-3xl md:text-4xl font-bold text-white mt-4">
                Nieuw <span class="text-gym-primary">Artikel</span>
            </h1>
            <p class="text-gym-muted mt-2">
                Deel jouw kennis en ervaring met de community.
            </p>
        </div>

        <div class="card bg-gym-surface border border-gym-border shadow-xl">
            <div class="card-body">
                <form action="{{ route('artikelen.store') }}" method="POST" enctype="multipart/form-data" class="flex flex-col gap-6">
                    @csrf

                    <!-- Title -->
                    <div class="form-control w-full">
                        <label for="title" class="label">
                            <span class="label-text text-white font-medium">Titel</span>
                        </label>
                        <input type="text"
                               id="title"
                               name="title"
                               value="{{ old('title') }}"
                               placeholder="Bijv. De voordelen van creatine"
                               class="input input-bordered bg-gym-background border-gym-border focus:border-gym-primary focus:outline-none w-full @error('title') input-error @enderror"
                               required />
                        @error('title')
                            <label class="label">
                                <span class="label-text-alt text-error">{{ $message }}</span>
                            </label>
                        @enderror
                    </div>

                    <!-- Category -->
                    <div class="form-control w-full">
                        <label for="category" class="label">
                            <span class="label-text text-white font-medium">Categorie</span>
                        </label>
                        <select id="category"
                                name="category"
                                class="select select-bordered bg-gym-background border-gym-border focus:border-gym-primary focus:outline-none w-full @error('category') select-error @enderror"
                                required>
                            <option disabled selected value="">Kies een categorie</option>
                            @foreach(\App\Enums\PostCategoryEnum::cases() as $category)
                                <option value="{{ $category->value }}" {{ old('category') == $category->value ? 'selected' : '' }}>
                                    {{ $category->label() }}
                                </option>
                            @endforeach
                        </select>
                        @error('category')
                            <label class="label">
                                <span class="label-text-alt text-error">{{ $message }}</span>
                            </label>
                        @enderror
                    </div>

                    <!-- Image Input -->
                    <div class="form-control w-full">
                        <label for="image" class="label">
                            <span class="label-text text-white font-medium">Afbeelding (Optioneel)</span>
                        </label>
                        <input type="file"
                               id="image"
                               name="image"
                               class="file-input file-input-bordered bg-gym-background border-gym-border focus:border-gym-primary w-full @error('image') file-input-error @enderror"
                               accept="image/jpeg,image/png,image/jpg,image/webp" />
                        <label class="label">
                            <span class="label-text-alt text-gym-muted">Max. 2MB (JPEG, PNG, WEBP)</span>
                        </label>
                        @error('image')
                            <label class="label">
                                <span class="label-text-alt text-error">{{ $message }}</span>
                            </label>
                        @enderror
                    </div>

                    <!-- Body  -->
                    <div class="form-control w-full">
                        <label for="body" class="label">
                            <span class="label-text text-white font-medium">Inhoud</span>
                        </label>
                        <textarea id="body"
                                  name="body"
                                  placeholder="Schrijf hier je artikel..."
                                  class="textarea textarea-bordered bg-gym-background border-gym-border focus:border-gym-primary focus:outline-none h-64 w-full @error('body') textarea-error @enderror"
                                  required>{{ old('body') }}</textarea>
                        @error('body')
                            <label class="label">
                                <span class="label-text-alt text-error">{{ $message }}</span>
                            </label>
                        @enderror
                    </div>

                    <!-- Submit  -->
                    <div class="card-actions justify-end mt-4">
                        <button type="submit" class="btn bg-gym-primary text-gym-background hover:bg-gym-accent font-bold w-full md:w-auto">
                            <i data-lucide="send" class="w-4 h-4 mr-2"></i>
                            Publiceren
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</x-app-layout>
