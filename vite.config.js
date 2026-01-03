import { defineConfig } from 'vite';
import laravel from 'laravel-vite-plugin';

export default defineConfig({
    plugins: [
        laravel({
            input: ['resources/css/app.css', 'resources/js/app.js'],
            refresh: true,
        }),
    ],
    css: {
        devSourcemap: false,
    },
    server: {
        host: '0.0.0.0',
        port: Number(process.env.VITE_PORT) || 5173,
        hmr: {
            host: 'localhost',
            port: Number(process.env.VITE_PORT) || 5173,
        },
        watch: {
            usePolling: true,
            interval: 1000,
            binaryInterval: 3000,
            ignored: [
                '**/.git/**',
                '**/node_modules/**',
                '**/vendor/**',
                '**/storage/**',
                '**/public/**',
                '**/database/**',
                '**/tests/**'
            ],
        },
    },
});
