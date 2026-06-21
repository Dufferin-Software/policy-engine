/** @type {import('tailwindcss').Config} */

// Theme-aware palette. Every shade resolves to a CSS variable defined in
// src/index.css, so the same utility classes (bg-gray-800, text-blue-400, …)
// follow the active light/dark theme without per-component `dark:` variants.
// The dark values are the stock Tailwind palette, so the dark theme is
// byte-for-byte identical to before this indirection was introduced.
const themed = (family) =>
  Object.fromEntries(
    [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950].map((shade) => [
      shade,
      `rgb(var(--c-${family}-${shade}) / <alpha-value>)`,
    ]),
  )

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        gray: themed('gray'),
        blue: themed('blue'),
        sky: themed('sky'),
        red: themed('red'),
        rose: themed('rose'),
        green: themed('green'),
        emerald: themed('emerald'),
        yellow: themed('yellow'),
        amber: themed('amber'),
        orange: themed('orange'),
        purple: themed('purple'),
        cyan: themed('cyan'),
        teal: themed('teal'),
      },
    },
  },
  plugins: [],
}
