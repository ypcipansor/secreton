/** @type {import('tailwindcss').Config} */
module.exports = {
  // Scanning the .rs sources is what makes the local build work: Tailwind reads the
  // class names out of the `view!` macros. This file had no effect before, because the
  // page loaded Tailwind from a CDN at runtime instead of compiling it.
  content: ["./src/**/*.rs"],
  theme: { extend: {} },
  plugins: [],
};
