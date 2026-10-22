import { FlatCompat } from "@eslint/eslintrc";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({ baseDirectory: __dirname });

/**
 * V21 quality gate: non-interactive ESLint CLI (replaces the deprecated,
 * config-less `next lint`). Next.js 15 still ships a legacy (eslintrc)
 * config, so it is bridged through FlatCompat.
 */
const config = [
  {
    ignores: [".next/**", "next-env.d.ts", "coverage/**"],
  },
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    rules: {
      // Tests assert against thrown errors and partial fetch mocks, so an
      // unused catch binding is intentional documentation there.
      "no-empty": ["error", { allowEmptyCatch: true }],
      // `_args` / `_scope` mark intentionally unused mock parameters.
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" },
      ],
    },
  },
];

export default config;
