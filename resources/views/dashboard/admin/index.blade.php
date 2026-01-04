@use('App\Models\Post')
@use('App\Models\User')

<x-app-layout>
    <div class="space-y-6 pb-12 px-4 sm:px-0">

        {{-- Stats Grid --}}
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <x-dashboard.admin.stats-card
                title="Totaal Leden"
                :value="User::count()"
                icon="users"
            />

            <x-dashboard.admin.stats-card
                title="Artikelen"
                :value="Post::count()"
                icon="file-text"
            />

            <x-dashboard.admin.stats-card
                title="Actieve Tab"
                :value="$tab"
                icon="layout"
                value-class="text-2xl uppercase"
            />
        </div>

        {{-- Tab Navigatie --}}
        <x-dashboard.admin.tab-navigation
            :active-tab="$tab"
            :tabs="[
        'users' => 'Gebruikers',
        'posts' => 'Artikelen',
        'roles' => 'Rollen',
        'permissions' => 'Permissies'
    ]"
        />

        {{-- tab filter --}}
        <div class="bg-gym-surface border border-gym-border rounded-lg overflow-hidden shadow-sm">
            <div class="p-6">
                <x-dashboard.admin.tab-filter
                    :tab="$tab"
                    :categories="$categories"
                    :roles="$roles"
                    :permissions="$permissions"
                />

                <x-dashboard.admin.data-table
                    :tab="$tab"
                    :items="$items"
                />

                <div class="mt-8">
                    {{ $items->links() }}
                </div>
            </div>
        </div>

        {{-- Pagination --}}
        <div class="mt-8">
            {{ $items->links() }}
        </div>
    </div>
    </div>
    </div>

    <script>
        lucide.createIcons();
    </script>
</x-app-layout>
