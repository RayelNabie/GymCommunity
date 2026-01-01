<x-app-layout class="!max-w-none !p-0">

    {{-- hero section --}}
    <x-landing_page.hero/>

    {{-- feature blocks --}}
    <section id="features" class="py-32 bg-zinc-900">
        <div class="container mx-auto px-4">
            <div class="text-left mb-16">
                <h2 class="text-3xl lg:text-4xl font-bold text-white mb-4">De ultieme gym-hub</h2>
                <p class="text-gray-400 max-w-2xl">Alles wat je nodig hebt om te groeien samen met andere atleten.</p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <x-landing_page.feature-card
                    icon="messages-square"
                    title="Community Denktank"
                    description="De plek voor al je vragen over training, voeding en herstel. Krijg antwoord van de community."
                />

                <x-landing_page.feature-card
                    icon="book-open"
                    title="Interactieve Logs"
                    description="Deel je schema's en progressie. Laat anderen meekijken en krijg feedback op je route naar succes."
                />

                <x-landing_page.feature-card
                    icon="award"
                    title="Expert Geverifieerd"
                    description="Herken waardevol advies direct door badges voor gecertificeerde trainers en ervaren forumleden."
                />

                <x-landing_page.feature-card
                    icon="search"
                    title="Slimme Zoekfunctie"
                    description="Vind razendsnel eerdere discussies over specifieke oefeningen, supplementen of blessures."
                />

                <x-landing_page.feature-card
                    icon="send"
                    title="Direct Messaging"
                    description="Leg 1-op-1 contact met trainingsmaatjes om af te spreken of dieper op techniek in te gaan."
                />

                <x-landing_page.feature-card
                    icon="trending-up"
                    title="Trending Discussies"
                    description="Blijf op de hoogte van wat er nu leeft in de gym, van nieuwe hypes tot wetenschappelijke doorbraken."
                />
            </div>
        </div>
    </section>

    {{-- CTA to register --}}
    <x-landing_page.cta-section/>
</x-app-layout>
