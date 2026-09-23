#!/usr/bin/env node
// Checks the package as npm will publish it, outside the repository:
//
//   1. `npm pack`, then install the tarball in a temporary project together
//      with its dependencies from the registry.
//   2. Compile the consumers in types-test/ (*.ts ESM, *.cts CommonJS)
//      against the installed package with skipLibCheck: false: NodeNext,
//      Node16 and Bundler with the TypeScript of this repository, and Node16
//      with the oldest supported TypeScript (MIN_TYPESCRIPT: the first release
//      with node16, or package.json#config.minTypeScript when the package's
//      declarations need a later one).
//   3. Load every entry point of package.json#exports at runtime: `import`,
//      `require` and plain (global bundle) targets. Wildcard subpaths and
//      package.json are skipped.
//   4. For every `import` / `require` condition, check that its declarations
//      have the module format of the file they describe (ESM for `import`,
//      CommonJS for `require`; TypeScript decides it from the extension and
//      package.json#type) and that they declare exactly the values the module
//      exports at runtime, using the TypeScript compiler API.
//
// Needs network access to the npm registry. Run with `npm run test:package`.
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const MIN_TYPESCRIPT = pkg.config?.minTypeScript ?? "4.7.4";
const ts = createRequire(join(ROOT, "package.json"))("typescript");

const failures = [];
function step(label, fn) {
  try {
    const detail = fn();
    console.log(`ok   ${label}${detail ? ` — ${detail}` : ""}`);
  } catch (error) {
    failures.push(label);
    const output = `${error.stdout ?? ""}${error.stderr ?? ""}`.trim();
    console.log(`FAIL ${label}\n${output || error.message}`);
  }
}

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

/** Module format TypeScript gives a declaration file of this package. */
function declarationFormat(file) {
  if (file.endsWith(".d.mts")) return "esm";
  if (file.endsWith(".d.cts")) return "commonjs";
  return pkg.type === "module" ? "esm" : "commonjs";
}

/** Names of the values (not types) a declaration file exports. */
function declaredValueExports(file) {
  const program = ts.createProgram([file], {
    module: ts.ModuleKind.Node16,
    moduleResolution: ts.ModuleResolutionKind.Node16,
    noEmit: true,
    skipLibCheck: true,
    types: [],
  });
  const checker = program.getTypeChecker();
  const moduleSymbol = checker.getSymbolAtLocation(program.getSourceFile(file));
  const isTypeOnly = (symbol) =>
    (symbol.declarations ?? []).some(
      (d) => ts.isExportSpecifier(d) && (d.isTypeOnly || d.parent.parent.isTypeOnly),
    );
  return checker
    .getExportsOfModule(moduleSymbol)
    .filter((symbol) => {
      if (isTypeOnly(symbol)) return false;
      const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
      return (target.flags & ts.SymbolFlags.Value) !== 0;
    })
    .map((symbol) => symbol.escapedName)
    .sort();
}

/** [subpath, conditions] for every entry of package.json#exports. */
function entries() {
  const exportsField = pkg.exports ?? {};
  return Object.entries(exportsField).map(([subpath, target]) => [
    subpath,
    typeof target === "string" ? { default: target } : target,
  ]);
}

const work = mkdtempSync(join(tmpdir(), "neurai-package-check-"));
try {
  const tarball = run("npm", ["pack", "--pack-destination", work, "--silent"], ROOT).trim().split("\n").pop();
  const app = join(work, "app");
  cpSync(join(ROOT, "types-test"), join(app, "types-test"), { recursive: true });
  writeFileSync(join(app, "package.json"), JSON.stringify({ name: "package-consumer", private: true, type: "module" }));
  const repoTypeScript = ts.version;
  run(
    "npm",
    [
      "install",
      "--no-audit",
      "--no-fund",
      join(work, tarball),
      `typescript@${repoTypeScript}`,
      `typescript-min@npm:typescript@${MIN_TYPESCRIPT}`,
    ],
    app,
  );

  const files = readdirSync(join(app, "types-test"))
    .filter((f) => /\.(c|m)?ts$/.test(f))
    .map((f) => `types-test/${f}`);
  const base = {
    strict: true,
    noEmit: true,
    skipLibCheck: false,
    target: "ES2022",
    lib: ["ES2022", "DOM"],
    types: [],
  };
  const configs = [
    ["NodeNext", "NodeNext", "typescript", repoTypeScript],
    ["Node16", "Node16", "typescript", repoTypeScript],
    ["Preserve", "Bundler", "typescript", repoTypeScript],
    ["Node16", "Node16", "typescript-min", MIN_TYPESCRIPT],
  ];
  for (const [module, moduleResolution, compiler, version] of configs) {
    const name = `tsconfig.${moduleResolution.toLowerCase()}.${compiler}.json`;
    writeFileSync(join(app, name), JSON.stringify({ compilerOptions: { ...base, module, moduleResolution }, files }, null, 2));
    step(`types: ${moduleResolution} with TypeScript ${version} (${files.length} consumers)`, () => {
      run("node", [join(app, "node_modules", compiler, "bin/tsc"), "-p", name], app);
    });
  }

  const probe = (code, type) =>
    run("node", type === "module" ? ["--input-type=module", "-e", code] : ["-e", code], app).trim();
  const installed = (file) => join(app, "node_modules", pkg.name, file);

  function checkDeclarations(specifier, condition, types, expectedFormat, runtime) {
    step(`declarations: "${specifier}" ${condition} types (${types ?? "none"})`, () => {
      if (!types) throw new Error(`the ${condition} condition has no declarations`);
      const format = declarationFormat(types);
      if (format !== expectedFormat) {
        throw new Error(`TypeScript reads ${types} as ${format}, but the ${condition} entry is ${expectedFormat}`);
      }
      const declared = declaredValueExports(installed(types));
      if (JSON.stringify(declared) !== JSON.stringify(runtime)) {
        const missing = runtime.filter((k) => !declared.includes(k));
        const extra = declared.filter((k) => !runtime.includes(k));
        throw new Error(`not declared: [${missing}] — declared but missing at runtime: [${extra}]`);
      }
      return `${format}, ${declared.length} values = runtime`;
    });
  }

  for (const [subpath, conditions] of entries()) {
    const specifier = subpath === "." ? pkg.name : `${pkg.name}/${subpath.replace(/^\.\//, "")}`;
    if (subpath.includes("*") || subpath.endsWith(".json")) {
      console.log(`skip ${specifier}`);
      continue;
    }
    const typesOf = (condition) =>
      typeof conditions[condition] === "object" ? conditions[condition].types : conditions.types;
    if (conditions.import) {
      let runtime = [];
      step(`runtime: import "${specifier}"`, () => {
        runtime = JSON.parse(
          probe(`const m = await import(${JSON.stringify(specifier)}); console.log(JSON.stringify(Object.keys(m).sort()))`, "module"),
        );
        return `${runtime.length} exports`;
      });
      checkDeclarations(specifier, "import", typesOf("import"), "esm", runtime);
    }
    if (conditions.require) {
      let runtime = [];
      step(`runtime: require "${specifier}"`, () => {
        runtime = JSON.parse(
          probe(`console.log(JSON.stringify(Object.keys(require(${JSON.stringify(specifier)})).filter((k) => k !== "__esModule").sort()))`, "commonjs"),
        );
        return `${runtime.length} exports`;
      });
      checkDeclarations(specifier, "require", typesOf("require"), "commonjs", runtime);
    }
    if (conditions.default && !conditions.import && !conditions.require) {
      step(`runtime: load "${specifier}"`, () => {
        const before = "Object.keys(globalThis).length";
        return probe(`const n = ${before}; require(${JSON.stringify(specifier)}); console.log("+" + (${before} - n) + " globals")`, "commonjs");
      });
    }
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}

if (failures.length > 0) {
  console.log(`\n${failures.length} check(s) failed: ${failures.join("; ")}`);
  process.exit(1);
}
console.log("\npackage checks passed");
