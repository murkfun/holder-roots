// src/entry.mjs isMain: the scripts' "am I the entry point" check matches paths a hand-built file:// URL would not
// (spaces, symlinks such as the npm bin link), so `npm run verify-bytecode` and the CLI never exit 0 having done nothing.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { isMain } from "../src/entry.mjs";

test("isMain: a path with spaces and a symlinked entry point still match; another file does not", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "murkfun holders entry "));
  try {
    const f = path.join(dir, "a b.mjs");
    fs.writeFileSync(f, "");
    assert.equal(`file://${f}` === pathToFileURL(f).href, false, "the naive URL differs here");
    assert.equal(isMain(pathToFileURL(f).href, f), true);
    const link = path.join(dir, "bin link");
    fs.symlinkSync(f, link);
    assert.equal(isMain(pathToFileURL(f).href, link), true);
    assert.equal(isMain(pathToFileURL(f).href, path.join(dir, "other.mjs")), false);
    assert.equal(isMain(pathToFileURL(f).href, undefined), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the CLI runs from a checkout whose path has a space", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "murkfun holders cli "));
  try {
    const root = path.resolve(import.meta.dirname, "..");
    fs.cpSync(path.join(root, "src"), path.join(dir, "src"), { recursive: true });
    fs.symlinkSync(path.join(root, "node_modules"), path.join(dir, "node_modules"));
    fs.copyFileSync(path.join(root, "package.json"), path.join(dir, "package.json"));
    const out = execFileSync(process.execPath, [path.join(dir, "src", "cli.mjs"), "--help"], { encoding: "utf8" });
    assert.match(out, /^murkfun-holders: check MurkFun's holder set/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
