import colors from 'tailwindcss/colors'
import daisyui from 'daisyui'

/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./resources/**/*.blade.php",
        "./resources/**/*.js",
        "./resources/**/*.vue",
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
        daisyui,
    ],
}
