import toruslabsTypescript from "@toruslabs/eslint-config-typescript";

export default [
  {
    ignores: ["dist/**", "babel.config.js"],
  },
  ...toruslabsTypescript,
  {
    rules: {
      "no-unused-vars": "off",
      "no-implicit-any": "off",
    },
  },
  {
    files: ["test/**"],
    rules: {
      "import/no-extraneous-dependencies": "off",
    },
  },
];
