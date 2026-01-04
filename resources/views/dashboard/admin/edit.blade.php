<x-app-layout>
    <x-slot name="header">
        <div class="flex justify-between items-center">
            <h2 class="font-semibold text-xl text-white leading-tight">
                {{ __('User Management') }}
            </h2>
            <span class="text-xs text-gym-muted font-mono uppercase">ID: {{ $user->getKey() }}</span>
        </div>
    </x-slot>

    <div class="py-12">
        <div class="max-w-4xl mx-auto sm:px-6 lg:px-8 space-y-6">

            {{-- 1. User Info Header Block --}}
            <div class="bg-gym-surface border border-gym-border rounded-lg shadow-sm overflow-hidden">
                <div class="p-6 flex items-center gap-6">
                    <div class="bg-gym-primary/10 p-4 rounded-full">
                        <i data-lucide="user" class="size-8 text-gym-primary"></i>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-8 flex-1">
                        <div>
                            <p class="text-[10px] uppercase tracking-wider text-gym-muted">Full Name</p>
                            <p class="text-white font-bold text-lg">{{ $user->name }}</p>
                        </div>
                        <div>
                            <p class="text-[10px] uppercase tracking-wider text-gym-muted">Email Address</p>
                            <p class="text-white">{{ $user->email }}</p>
                        </div>
                        <div>
                            <p class="text-[10px] uppercase tracking-wider text-gym-muted">Member Since</p>
                            <p class="text-white">{{ $user->created_at->format('d M Y') }}</p>
                        </div>
                    </div>
                </div>
            </div>

            {{-- 2. Role Selection Form --}}
            <form action="{{ route('users.update', $user) }}" method="POST" class="space-y-6">
                @csrf
                @method('PUT')

                <div class="bg-gym-surface border border-gym-border rounded-lg shadow-sm overflow-hidden">
                    <div class="bg-gym-surface-hover px-6 py-4 border-b border-gym-border">
                        <h3 class="text-white font-bold flex items-center gap-2">
                            <i data-lucide="shield-check" class="size-5 text-gym-primary"></i>
                            Assign Role
                        </h3>
                        <p class="text-xs text-gym-muted mt-1 italic">Selecting a role automatically updates the user's permissions.</p>
                    </div>

                    <div class="p-6 space-y-4">
                        @foreach($availableRoles as $roleModel)
                            @php
                                $roleEnum = $roleModel->name instanceof \App\Enums\RoleEnum
                                    ? $roleModel->name
                                    : \App\Enums\RoleEnum::from($roleModel->name);
                            @endphp

                            <div class="p-4 rounded-md bg-gym-background/50 border border-gym-border hover:border-gym-primary transition-all">
                                <label class="flex items-start gap-4 cursor-pointer group">
                                    <input type="radio" name="role" value="{{ $roleEnum->value }}"
                                           {{ $user->roles->contains('name', $roleEnum->value) ? 'checked' : '' }}
                                           class="radio radio-primary border-gym-border mt-1">

                                    <div class="flex-1">
                                        <span class="text-white font-bold group-hover:text-gym-primary transition-colors">
                                            {{ $roleEnum->name }}
                                        </span>

                                        <div class="mt-3">
                                            <p class="text-[10px] uppercase tracking-wider text-gym-muted mb-1">Included Permissions:</p>
                                            <ul class="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1">
                                                @forelse($roleModel->permissions as $permModel)
                                                    @php
                                                        $permEnum = $permModel->name instanceof \App\Enums\PermissionEnum
                                                            ? $permModel->name
                                                            : \App\Enums\PermissionEnum::from($permModel->name);
                                                    @endphp
                                                    <li class="text-xs text-gym-text-light flex items-center gap-2">
                                                        <span class="text-gym-primary text-lg">·</span>
                                                        {{ $permEnum->description() }}
                                                    </li>
                                                @empty
                                                    <li class="text-xs text-gym-muted italic">No permissions assigned.</li>
                                                @endforelse
                                            </ul>
                                        </div>
                                    </div>
                                </label>
                            </div>
                        @endforeach
                    </div>
                </div>

                {{-- Form Actions --}}
                <div class="flex items-center justify-end gap-4">
                    <a href="{{ route('admin.index', ['tab' => 'users']) }}"
                       class="text-gym-muted hover:text-white transition-colors text-sm">
                        Cancel and go back
                    </a>
                    <button type="submit" class="bg-gym-primary hover:bg-yellow-500 text-black font-bold py-2.5 px-10 rounded-md transition-colors shadow-lg">
                        Update Role
                    </button>
                </div>
            </form>
        </div>
    </div>
</x-app-layout>
