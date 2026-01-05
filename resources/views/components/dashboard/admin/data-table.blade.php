@props(['tab', 'items'])

<div class="overflow-x-auto">
    <table class="table w-full text-gym-text-light">
        <thead>
        <tr class="text-gym-muted border-b border-gym-border text-left">
            @if($tab === 'posts')
                <th class="pb-3">Titel</th>
                <th class="pb-3">Auteur</th>
                <th class="pb-3">Categorie</th>
                <th class="pb-3 text-right">Acties</th>
            @else
                <th class="pb-3">Naam</th>
                <th class="pb-3">E-mail</th>
                <th class="pb-3">Rollen</th>
                <th class="pb-3 text-right">Acties</th>
            @endif
        </tr>
        </thead>
        <tbody>
        @forelse($items as $item)
            <tr class="hover:bg-gym-surface-hover border-b border-gym-border transition-colors">
                @if($tab === 'posts')
                    <td class="py-4 font-bold text-white">{{ $item->title }}</td>
                    <td class="py-4">{{ $item->user->name }}</td>
                    <td class="py-4">
                        <span class="bg-gym-surface-hover px-2 py-1 rounded border border-gym-border text-xs uppercase">
                            {{ $item->category->name }}
                        </span>
                    </td>
                    <td class="py-4 text-right">
                        <div class="flex justify-end items-center gap-2">
                            @can('update', $item)
                                <x-shared.status-toggle 
                                    :item="$item" 
                                    route="artikelen.toggle-active" 
                                    tooltip-position="left" 
                                />

                                <a href="{{ route('artikelen.edit', $item) }}"
                                   class="text-gym-primary hover:underline">Aanpassen</a>
                            @endcan
                        </div>
                    </td>
                @else
                    <td class="py-4 font-bold text-white">
                        {{ $item->name }}
                        @if(auth()->user()->is($item))
                            <span class="ml-2 text-[8px] bg-gym-primary/10 text-gym-primary border border-gym-primary/20 px-1.5 py-0.5 rounded uppercase tracking-tighter">You</span>
                        @endif
                    </td>
                    <td class="py-4">{{ $item->email }}</td>
                    <td class="py-4">
                        <div class="flex gap-1 flex-wrap">
                            @foreach($item->roles as $role)
                                <span class="badge badge-outline border-gym-primary text-gym-primary text-[10px] uppercase">
                                    {{ $role->name }}
                                </span>
                            @endforeach
                        </div>
                    </td>
                    <td class="py-4 text-right">
                        <div class="flex justify-end items-center gap-2">
                            @can('update', $item)
                                <a href="{{ route('users.edit', $item) }}"
                                   class="btn btn-sm btn-outline border-gym-border text-gym-primary hover:bg-gym-primary hover:text-black transition-all">
                                    Aanpassen
                                </a>
                            @endcan

                            @can('delete', $item)
                                <x-shared.delete-popup
                                    :action="route('users.destroy', $item)"
                                    buttonText="Verwijderen"
                                    class="btn-sm border-red-500/50 text-red-500 hover:bg-red-500 hover:text-white"
                                />
                            @else
                                @if(auth()->user()->is($item))
                                    <span class="text-[10px] text-gym-muted italic pr-2">Actions restricted</span>
                                @endif
                            @endcan
                        </div>
                    </td>
                @endif
            </tr>
        @empty
            <tr>
                <td colspan="4" class="py-12 text-center text-gym-muted">
                    Geen resultaten gevonden voor deze selectie.
                </td>
            </tr>
        @endforelse
        </tbody>
    </table>
</div>
