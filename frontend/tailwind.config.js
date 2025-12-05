/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}"
  ],
  theme: {
    extend: {
      fontFamily: {
        display: ['"Space Grotesk"', 'Inter', 'system-ui', 'sans-serif'],
        body: ['Inter', 'system-ui', 'sans-serif']
      },
      boxShadow: {
        glass: '0 20px 80px rgba(0,0,0,0.35)'
      },
      colors: {
        brand: {
          400: '#7C6FF6',
          500: '#6A5AE0',
          600: '#5743C0'
        }
      }
    }
  },
  plugins: []
}
