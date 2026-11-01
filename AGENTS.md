# AGENTS.md

Single-package Express 5 + MongoDB API server. All runtime code currently lives in `server.ts` (entrypoint, no `src/`).

## Commands

| Task | Command |
| --- | --- |
| Dev server (watch, no build) | `npm run dev` (`tsx watch server.ts`) |
| Typecheck | `npx tsc --noEmit` |
| Build | `npm run build` (`tsc`) |
| Run built output | `npm start` — **currently broken, see below** |

There is no test runner, linter, formatter config, or CI. Do not invent `npm test`/`npm run lint`; use `npx tsc --noEmit` as the verification step.

## Build gotcha

`tsconfig.json` has `outDir` commented out, so `npm run build` emits `server.js`/`.d.ts`/`.map` **into the repo root**, while `npm start` runs `node dist/server.js` (does not exist). To produce a runnable build, either add `"outDir": "./dist"` to `tsconfig.json` or run `npx tsc --outDir dist`. Clean up stray root-level `server.js`/`server.d.ts*` if you build without it.

## Environment

- `.env` is gitignored but present locally and contains **real MongoDB credentials**. Never print, commit, or copy its contents.
- Required: `MONGODB_URI` (throws at module load if missing). Optional: `PORT` (default `5000`), `DB_NAME` (falls through to the driver default if unset).
- `import "dotenv/config"` loads `.env` automatically; no dotenv setup elsewhere.

## Runtime behavior

- DB connect and index creation happen inside the `app.listen` callback (`connectDB`). The HTTP port is open before MongoDB is ready, so startup errors surface in logs, not as a failed bind.
- Indexes created on every startup (keep in sync when changing schemas):
  - `user.email` unique
  - `event.date`
  - `event.createdByEmail`
  - `data` compound `{ eventId, userEmail }` unique
- Collections (`user`, `event`, `data`) are referenced directly from `db.collection(...)`; MongoDB creates them lazily.
- Only route today is `GET /` health text. New routes go on `app` in `server.ts` unless the file is deliberately split.

## TypeScript conventions

- ESM (`"type": "module"`, `module: nodenext`): relative imports of local `.ts` files must use a `.js` extension.
- `verbatimModuleSyntax` + `isolatedModules`: use `import type` / inline `type` for type-only imports (as `server.ts` does).
- `strict`, `noUncheckedIndexedAccess`, and `exactOptionalPropertyTypes` are on; handle possibly-`undefined` values from indexes and optional properties.
- Express 5: async handler rejections are forwarded automatically; wildcard routes use `/*splat`, not `*`.
