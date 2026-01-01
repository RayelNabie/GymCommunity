<header
    class="navbar bg-gym-background container mx-auto px-4 py-4 sticky top-0 z-50 bg-opacity-60 backdrop-blur border-b border-opacity-60 border-gym-primary"
    x-data="{ mobileMenuOpen: false }">
    <div class="navbar-start">
        <div class="lg:hidden">
            <button @click="mobileMenuOpen = !mobileMenuOpen" class="btn btn-ghost text-white">
                <i data-lucide="menu" class="w-6 h-6"></i>
            </button>
        </div>
        <a href="{{ url('/') }}" class="btn btn-ghost text-2xl font-bold text-gym-primary gap-2 hover:bg-gym-surface">
            <i data-lucide="dumbbell" class="w-8 h-8"></i>
            <span class="underline hidden sm:inline">GymCommunity.</span>
        </a>
    </div>
    <nav class="navbar-center hidden lg:flex gap-8">
        <a href="{{ url('/') }}"
           class="text-base font-medium {{ request()->is('/') ? 'text-gym-primary' : 'text-gym-text-light hover:text-gym-primary' }} transition-colors">Home</a>
        <a href="{{ route('artikelen.index') }}"
           class="text-base font-medium {{ request()->routeIs('artikelen.index') ? 'text-gym-primary' : 'text-gym-text-light hover:text-gym-primary' }} transition-colors">Artikelen</a>
    </nav>
    <div class="navbar-end gap-2 hidden lg:flex">
        @if (Route::has('login'))
            @auth
                <a href="{{ url('/dashboard') }}"
                   class="btn btn-sm btn-outline btn-primary hover:bg-gym-primary hover:text-gym-background">Dashboard</a>
                <form method="POST" action="{{ route('logout') }}">
                    @csrf
                    <button type="submit"
                            class="btn btn-sm btn-outline btn-primary px-4 hover:bg-red-600 ">
                        <i data-lucide="log-out" class="w-4 h-4"></i>
                    </button>
                </form>
            @else
                <a href="{{ route('login') }}" class="btn btn-sm btn-ghost text-white hover:text-gym-primary">Log in</a>
                @if (Route::has('register'))
                    <a href="{{ route('register') }}"
                       class="btn btn-sm bg-gym-primary hover:bg-yellow-400 text-black border-none font-bold">Sign
                        up</a>
                @endif
            @endauth
        @endif
    </div>

    <!-- Mobile Menu -->
    <div x-show="mobileMenuOpen"
         @click.away="mobileMenuOpen = false"
         class="absolute top-full left-0 w-full bg-gym-surface border-b border-gym-border shadow-xl lg:hidden flex flex-col p-4 gap-2"
         style="display: none;">
        <a href="{{ url('/') }}"
           class="block px-4 py-2 hover:bg-gym-surface-hover rounded-lg hover:text-gym-primary transition-colors {{ request()->is('/') ? 'text-gym-primary' : '' }}">Home</a>
        <a href="{{ route('artikelen.index') }}"
           class="block px-4 py-2 hover:bg-gym-surface-hover rounded-lg hover:text-gym-primary transition-colors {{ request()->routeIs('artikelen.index') ? 'text-gym-primary' : '' }}">Artikelen</a>

        <!-- Mobile Auth Links -->
        @if (Route::has('login'))
            <div class="h-px bg-gym-divider my-1"></div>
            @auth
                <a href="{{ url('/dashboard') }}"
                   class="block px-4 py-2 hover:bg-gym-surface-hover rounded-lg hover:text-gym-primary transition-colors">Dashboard</a>
            @else
                <a href="{{ route('login') }}"
                   class="block px-4 py-2 hover:bg-gym-surface-hover rounded-lg hover:text-gym-primary transition-colors">Log
                    in</a>
                @if (Route::has('register'))
                    <a href="{{ route('register') }}"
                       class="block px-4 py-2 hover:bg-gym-surface-hover rounded-lg hover:text-gym-primary transition-colors">Sign
                        up</a>
                @endif
            @endauth
        @endif
    </div>
</header>
