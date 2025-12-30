import colors from 'tailwindcss/colors'
import forms from '@tailwindcss/forms';
import daisyui from 'daisyui'

/** @type {import('tailwindcss').Config} */
export default {
    content: [
        './vendor/laravel/framework/src/Illuminate/Pagination/resources/views/*.blade.php',
        './storage/framework/views/*.php',
        './resources/js/**/*.js',
        './resources/views/**/*.blade.php',
    ],
    theme: {
        extend: {
            fontFamily: {
                sans: ['Satoshi', 'sans-serif'],
            },
            colors: {
                gym: {
                    primary: colors.yellow[400],
                    secondary: colors.white,
                    accent: colors.yellow[200],
                    background: colors.black,
                    surface: colors.zinc[900],
                    'surface-hover': colors.zinc[800],
                    border: colors.zinc[800],
                    muted: colors.gray[400],
                    meta: colors.gray[500],
                    icon: colors.zinc[600],
                    divider: colors.zinc[700],
                    'text-light': colors.gray[300],
                }
            }
        }
    },
    plugins: [
        daisyui, forms
    ],
}
