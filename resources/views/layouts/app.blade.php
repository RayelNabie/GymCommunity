<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" class="scroll-smooth">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">

    <title>{{ isset($title) ? $title . ' | ' . config('app.name') : config('app.name') }}</title>

    <link rel="preconnect" href="https://fonts.bunny.net">
    <link href="https://fonts.bunny.net/css?family=figtree:400,700,900&display=swap" rel="stylesheet"/>
    <script src="https://unpkg.com/lucide@latest"></script>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="font-sans antialiased bg-black text-white selection:bg-gym-primary selection:text-black">
<div class="min-h-screen flex flex-col bg-gym-background">

    {{-- Header uit components/shared --}}
    <x-shared.navbar/>

    <main {{ $attributes->merge(['class' => 'flex-grow w-full max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8']) }}>
        {{ $slot }}
    </main>

    {{-- Footer uit components/shared --}}
    <x-shared.footer/>
</div>

{{-- Lucide Icons Initialisatie --}}

<script>
    lucide.createIcons();
</script>
</body>
</html>
