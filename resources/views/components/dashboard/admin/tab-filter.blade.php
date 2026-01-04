@props(['tab', 'categories' => [], 'roles' => [], 'permissions'=> []])

<form action="{{ route('admin.index') }}" method="GET" class="mb-6 flex flex-wrap gap-4 items-end">
    <input type="hidden" name="tab" value="{{ $tab }}">

    <div class="flex flex-col gap-1">
        <label class="text-xs text-gym-muted uppercase font-bold">Zoeken</label>
        <input type="text" name="search" value="{{ request('search') }}"
               placeholder="Typ om te zoeken..."
               class="bg-gym-surface-hover border-gym-border text-white rounded-md focus:ring-gym-primary">
    </div>

    @if($tab === 'posts')
        <div class="flex flex-col gap-1">
            <label class="text-xs text-gym-muted uppercase font-bold">Categorie</label>
            <select name="category" onchange="this.form.submit()"
                    class="bg-gym-surface-hover border-gym-border text-white rounded-md">
                <option value="">Alle Categorieën</option>
                @foreach($categories as $category)
                    <option value="{{ $category->value }}" {{ request('category') == $category->value ? 'selected' : '' }}>
                        {{ $category->name }}
                    </option>
                @endforeach
            </select>
        </div>
    @endif

    @if($tab === 'roles')
        <div class="flex flex-col gap-1">
            <label class="text-xs text-gym-muted uppercase font-bold">Rol Filter</label>
            <select name="role" onchange="this.form.submit()"
                    class="bg-gym-surface-hover border-gym-border text-white rounded-md">
                <option value="">Kies een rol</option>
                @foreach($roles as $role)
                    <option value="{{ $role->value }}" {{ request('role') == $role->value ? 'selected' : '' }}>
                        {{ $role->name }}
                    </option>
                @endforeach
            </select>
        </div>
    @endif


    @if($tab === 'permissions')
        <div class="flex flex-col gap-1">
            <label class="text-xs text-gym-muted uppercase font-bold">Permissie Filter</label>
            <select name="permission" onchange="this.form.submit()"
                    class="bg-gym-surface-hover border-gym-border text-white rounded-md">
                <option value="">Kies een rol</option>
                @foreach($permissions as $permission)
                    <option value="{{ $permission->value }}" {{ request('permission') == $permission->value ? 'selected' : '' }}>
                        {{ $permission->name }}
                    </option>
                @endforeach
            </select>
        </div>
    @endif

    <button type="submit"
            class="bg-gym-primary text-black px-6 py-2 rounded-md font-bold hover:bg-yellow-500 transition-colors">
        Filteren
    </button>

    <a href="{{ route('admin.index', ['tab' => $tab]) }}"
       class="text-gym-muted text-sm hover:underline pb-2">Reset</a>
</form>
