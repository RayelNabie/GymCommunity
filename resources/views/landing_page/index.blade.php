<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" data-theme="black">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ config('app.name', 'GymCommunity') }}</title>

    <!-- Fonts -->
    <link href="https://api.fontshare.com/v2/css?f[]=satoshi@300,400,500,700,900&display=swap" rel="stylesheet">

    <!-- DaisyUI & Tailwind CSS -->
    @vite(['resources/css/app.css', 'resources/js/app.js'])

    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>
</head>
<body class="flex flex-col min-h-screen bg-black">

<!-- Navbar -->
<x-shared.navbar />

<main>
    <!-- Hero Section -->
    <section class="relative py-32 lg:py-48 overflow-hidden bg-black">
        <div class="container mx-auto px-4 flex flex-col-reverse lg:flex-row items-center gap-12">
            <!-- Text Content -->
            <div class="flex-1 text-center lg:text-left z-10">
                <h1 class="text-4xl lg:text-7xl font-bold leading-tight text-white mb-6">
                    Het forum voor<br>
                    <span class="text-gym-primary underline">Al je gymvragen</span>
                </h1>
                <p class="text-lg text-gray-400 mb-8 max-w-lg mx-auto lg:mx-0">
                    Geen vraag is te gek. Duik in de kennis van de groep en til je sportprestaties naar een hoger niveau
                    met community-gedreven advies
                </p>
                <div class="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start">
                    <a href="{{ route('register') }}"
                       class="btn btn-lg bg-gym-primary text-black border-none shadow-lg font-bold">
                        Meld je nu aan
                        <i data-lucide="arrow-right" class="w-5 h-5 ml-2"></i>
                    </a>
                    <a href="#features" class="btn btn-lg btn-ghost border-gym-light text-white">
                        Inloggen
                    </a>
                </div>
                <div class="mt-8 flex items-center justify-center lg:justify-start gap-4 text-sm text-gray-500">
                    <div class="flex items-center gap-1">
                        <i data-lucide="check-circle" class="w-4 h-4 text-gym-primary"></i> Gratis
                    </div>
                    <div class="flex items-center gap-1">
                        <i data-lucide="check-circle" class="w-4 h-4 text-gym-primary"></i> Actieve moderatie
                    </div>
                </div>
            </div>

            <!-- SVG Illustration -->
            <div class="flex-1 relative z-10">
                <svg viewBox="0 0 600 500" xmlns="http://www.w3.org/2000/svg" class="w-full h-auto drop-shadow-2xl">
                    <defs>
                        <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" style="stop-color:#FACC15;stop-opacity:1"/>
                            <stop offset="100%" style="stop-color:#000000;stop-opacity:1"/>
                        </linearGradient>
                    </defs>
                    <!-- Background Blob -->
                    <path fill="#18181B"
                          d="M45.7,-76.3C58.9,-69.3,69.1,-55.6,76.3,-41.2C83.5,-26.8,87.7,-11.7,85.6,2.5C83.5,16.7,75.1,30,65.3,41.2C55.5,52.4,44.3,61.5,31.8,68.3C19.3,75.1,5.5,79.6,-7.1,77.8C-19.7,76,-31.1,67.9,-41.8,59.1C-52.5,50.3,-62.5,40.8,-69.8,29.1C-77.1,17.4,-81.7,3.5,-79.6,-9.4C-77.5,-22.3,-68.7,-34.2,-58.2,-43.5C-47.7,-52.8,-35.5,-59.5,-23.2,-67.1C-10.9,-74.7,1.5,-83.2,14.8,-84.2C28.1,-85.2,42.3,-78.7,45.7,-76.3Z"
                          transform="translate(300 250) scale(2.8)"/>

                    <!-- Lucide Biceps Flexed Icon -->
                    <svg x="150" y="100" width="300" height="300" viewBox="0 0 24 24" fill="none" stroke="#FACC15"
                         stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
                        <path
                            d="M12.409 13.017A5 5 0 0 1 22 15c0 3.866-4 7-9 7-4.077 0-8.153-.82-10.371-2.462-.426-.316-.631-.832-.62-1.362C2.118 12.723 2.627 2 10 2a3 3 0 0 1 3 3 2 2 0 0 1-2 2c-1.105 0-1.64-.444-2-1"/>
                        <path d="M15 14a5 5 0 0 0-7.584 2"/>
                        <path d="M9.964 6.825C8.019 7.977 9.5 13 8 15"/>
                    </svg>
                </svg>
            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section id="features" class="py-32 bg-zinc-900">
        <div class="container mx-auto px-4">
            <div class="text-left mb-16">
                <h2 class="text-3xl lg:text-4xl font-bold text-white mb-4">De ultieme gym-hub</h2>
                <p class="text-gray-400 max-w-2xl">
                    Alles wat je nodig hebt om kennis te delen, vragen te stellen en te groeien samen met andere
                    atleten.
                </p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <article class="card bg-zinc-800 shadow-xl border border-zinc-700">
                    <div class="card-body">
                        <div
                            class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-gym-primary">
                            <i data-lucide="messages-square" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Community Denktank</h3>
                        <p class="text-gray-400">De plek voor al je vragen over training, voeding en herstel. Krijg
                            antwoord van de community.</p>
                    </div>
                </article>

                <article class="card bg-zinc-800 shadow-xl border border-zinc-700">
                    <div class="card-body">
                        <div
                            class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-gym-primary">
                            <i data-lucide="book-open" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Interactieve Logs</h3>
                        <p class="text-gray-400">Deel je schema's en progressie. Laat anderen meekijken en krijg
                            feedback op je route naar succes.</p>
                    </div>
                </article>

                <article class="card bg-zinc-800 shadow-xl border border-zinc-700">
                    <div class="card-body">
                        <div
                            class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-gym-primary">
                            <i data-lucide="award" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Expert Geverifieerd</h3>
                        <p class="text-gray-400">Herken waardevol advies direct door badges voor gecertificeerde
                            trainers en ervaren forumleden.</p>
                    </div>
                </article>

                <article class="card bg-zinc-800 shadow-xl border border-zinc-700">
                    <div class="card-body">
                        <div
                            class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-gym-primary">
                            <i data-lucide="search" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Slimme Zoekfunctie</h3>
                        <p class="text-gray-400">Vind razendsnel eerdere discussies over specifieke oefeningen,
                            supplementen of blessures.</p>
                    </div>
                </article>

                <article class="card bg-zinc-800 shadow-xl border border-zinc-700">
                    <div class="card-body">
                        <div
                            class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-gym-primary">
                            <i data-lucide="send" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Direct Messaging</h3>
                        <p class="text-gray-400">Leg 1-op-1 contact met trainingsmaatjes om af te spreken of dieper op
                            techniek in te gaan.</p>
                    </div>
                </article>

                <article class="card bg-zinc-800 shadow-xl border border-zinc-700">
                    <div class="card-body">
                        <div
                            class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-gym-primary">
                            <i data-lucide="trending-up" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Trending Discussies</h3>
                        <p class="text-gray-400">Blijf op de hoogte van wat er nu leeft in de gym, van nieuwe hypes tot
                            wetenschappelijke doorbraken.</p>
                    </div>
                </article>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section class="py-32 bg-gym-primary text-black relative overflow-hidden">
        <div class="absolute top-0 left-0 -ml-20 -mt-20 w-64 h-64 rounded-full bg-black opacity-10"></div>
        <div class="absolute bottom-0 right-0 -mr-20 -mb-20 w-80 h-80 rounded-full bg-white opacity-20"></div>

        <div class="container mx-auto px-4 text-center relative z-10">
            <h2 class="text-3xl lg:text-5xl font-bold mb-6">Klaar om de diepte in te gaan?</h2>
            <p class="text-xl text-zinc-800 mb-10 max-w-2xl mx-auto">
                Word onderdeel van de grootste community-gedreven denktank en til je training naar een wetenschappelijk
                niveau.
            </p>
            <button class="btn bg-gym-light text-gym-primary px-8 py-3 font-bold uppercase tracking-wider">Meld je
                gratis aan
            </button>
        </div>
    </section>
</main>
<!-- Footer -->
<x-shared.footer />

<script>
    // Initialize Lucide Icons
    lucide.createIcons();
</script>
</body>
</html>
