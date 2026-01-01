@props(['action', 'buttonText' => 'Verwijderen'])

<div x-data="{ confirming: false }" class="inline-block">
    {{-- first state --}}
    <button x-show="!confirming"
            @click="confirming = true"
            type="button"
        {{ $attributes->merge(['class' => 'btn btn-outline btn-error']) }}>
        <i data-lucide="trash-2" class="size-4 mr-2"></i> {{ $buttonText }}
    </button>

    {{-- second state --}}
    <div x-show="confirming"
         x-cloak
         class="flex items-center gap-3 bg-gym-surface border border-gym-surface p-1 pl-4 rounded-xl shadow-xl">

        <span class="text-xs text-red-600 font-black uppercase tracking-widest">
            Weet je het zeker?
        </span>

        <div class="flex items-center gap-1">
            {{-- delete form --}}
            <form action="{{ $action }}" method="POST" class="inline">
                @csrf
                @method('DELETE')
                <button type="submit" class="btn btn-error btn-sm px-4 font-bold uppercase tracking-tighter hover:text-gym-primary">
                    Ja
                </button>
            </form>

            <button @click="confirming = false"
                    class="btn btn-ghost btn-sm text-gym-meta px-4 hover:text-gym-primary transition-colors">
                Nee
            </button>
        </div>
    </div>
</div>
