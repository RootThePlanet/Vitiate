import { defineConfig, type Plugin } from "vite";
import { resolve } from "path";
import { copyFile, rm } from "fs/promises";
import type { OutputBundle, OutputChunk } from "rollup";

/**
 * Rollup plugin that inlines chunk dependencies into content.js and wraps
 * the result in an IIFE.
 *
 * Chrome Manifest V3 content scripts run as classic scripts — they cannot
 * use ES module `import` statements.  Without this plugin the content
 * script silently fails with a SyntaxError and nothing executes.
 *
 * The background service worker and popup page are unaffected because
 * they are loaded as ES modules (`"type": "module"` / `<script type="module">`).
 */
function contentScriptIIFE(): Plugin {
  return {
    name: "vitiate-content-script-iife",
    generateBundle(_options: unknown, bundle: OutputBundle) {
      const contentEntry = bundle["content.js"];
      if (!contentEntry || contentEntry.type !== "chunk") return;

      // Collect all imported chunk sources in dependency order
      const visited = new Set<string>();
      const inlinedParts: string[] = [];

      function collectChunk(name: string): void {
        if (visited.has(name)) return;
        visited.add(name);
        const chunk = bundle[name];
        if (!chunk || chunk.type !== "chunk") return;
        // Recurse into the chunk's own imports first
        for (const dep of (chunk as OutputChunk).imports) collectChunk(dep);
        // Strip `export { … };` lines — the variables are already declared in scope
        const stripped = chunk.code.replace(/^export\s*\{[^}]*\};?\s*$/gm, "");
        inlinedParts.push(stripped);
      }

      for (const imp of (contentEntry as OutputChunk).imports) collectChunk(imp);

      // Strip `import { … } from '…';` lines from the content entry
      const contentCode = contentEntry.code.replace(
        /^import\s*\{[^}]*\}\s*from\s*['"][^'"]*['"];?\s*$/gm,
        "",
      );

      // Wrap everything in an IIFE so variables don't leak into the page scope
      contentEntry.code = `(function () {\n${inlinedParts.join("\n")}\n${contentCode}\n})();\n`;
      (contentEntry as OutputChunk).imports = [];
    },
  };
}

export default defineConfig(({ mode }) => {
  const isFirefoxBuild = mode === "firefox";
  const outDir = isFirefoxBuild ? "firefox-extension" : "chrome-extension";

  return {
    base: "./",
    build: {
      outDir,
      emptyOutDir: true,
      rollupOptions: {
        input: {
          background: resolve(__dirname, "src/background/background.ts"),
          content: resolve(__dirname, "src/content/content.ts"),
          popup: resolve(__dirname, "src/popup/popup.html"),
        },
        output: {
          entryFileNames: "[name].js",
          chunkFileNames: "chunks/[name]-[hash].js",
          assetFileNames: "assets/[name][extname]",
        },
        plugins: [contentScriptIIFE()],
      },
      target: "esnext",
      minify: false,
      sourcemap: false,
    },
    resolve: {
      alias: {
        "@": resolve(__dirname, "src"),
      },
    },
    publicDir: "public",
    plugins: [
      {
        name: "vitiate-firefox-manifest",
        async closeBundle() {
          if (!isFirefoxBuild) return;
          await copyFile(
            resolve(__dirname, "public/manifest.firefox.json"),
            resolve(__dirname, outDir, "manifest.json"),
          );
          await rm(resolve(__dirname, outDir, "manifest.firefox.json"), { force: true });
        },
      },
    ],
  };
});
