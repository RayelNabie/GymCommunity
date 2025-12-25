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
                    dark: colors.white,
                    light: colors.zinc[900],
                }
            }
        }
    },
    plugins: [
        daisyui, forms
    ],
}
