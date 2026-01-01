<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="csrf-token" content="{{ csrf_token() }}">

        <title>@isset($title){{ $title }} - @endisset{{ config('app.name', 'Laravel') }}</title>

        <!-- Fonts -->
        <link href="https://api.fontshare.com/v2/css?f[]=satoshi@300,400,500,700,900&display=swap" rel="stylesheet">

        <!-- DaisyUI & Tailwind CSS -->
        @vite(['resources/css/app.css', 'resources/js/app.js'])

        <!-- Lucide Icons -->
        <script src="https://unpkg.com/lucide@latest"></script>
    </head>
    <body class="flex flex-col min-h-screen bg-gym-background text-white antialiased">
        <x-shared.navbar />

        <!-- Page Content -->
        <main {{ $attributes->merge(['class' => 'flex-grow container mx-auto px-4 py-12']) }}>
            {{ $slot }}
        </main>

        <!-- Footer -->
        <x-shared.footer />

        <!-- Lucide Icons -->
        <script>
            lucide.createIcons();
        </script>
    </body>
</html>
