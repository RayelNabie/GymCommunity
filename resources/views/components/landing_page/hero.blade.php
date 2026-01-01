<section class="relative py-32 lg:py-48 overflow-hidden bg-black">
    <!-- Title -->
    <div class="container mx-auto px-4 flex flex-col-reverse lg:flex-row items-center gap-12">
        <div class="flex-1 text-center lg:text-left z-10">
            <h1 class="text-4xl lg:text-7xl font-bold leading-tight text-white mb-6">
                Het forum voor<br>
                <span class="text-gym-primary underline decoration-gym-primary/30">Al je gymvragen</span>
            </h1>
            <p class="text-lg text-gray-400 mb-8 max-w-lg mx-auto lg:mx-0">
                Geen vraag is te gek. Duik in de kennis van de groep en til je sportprestaties naar een hoger niveau.
            </p>
            <div class="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start">
                <a href="{{ route('register') }}"
                   class="btn btn-lg bg-gym-primary text-black border-none shadow-lg font-bold">
                    Meld je nu aan <i data-lucide="arrow-right" class="w-5 h-5 ml-2"></i>
                </a>
                <a href="{{ route('login') }}" class="btn btn-lg btn-ghost border-gym-light text-white">Inloggen</a>
            </div>
        </div>

        <!-- SVG Image -->
        <div class="flex-1 relative z-10 select-none pointer-events-none">
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
