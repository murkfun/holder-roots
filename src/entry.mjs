// Whether a module is the script node was started with. Compares file URLs built by node itself, so a path with
// spaces or other characters a URL escapes, a Windows path, or a symlink (the npm bin link) still matches: a
// hand-built `file://${process.argv[1]}` would not, and the command would then exit 0 having done nothing.
import fs from "node:fs";
import { pathToFileURL } from "node:url";

/** `moduleUrl` (the module's import.meta.url) is the entry script `argv1` (default process.argv[1]). */
export function isMain(moduleUrl, argv1 = process.argv[1]) {
  if (!argv1) return false;
  let real;
  try {
    real = fs.realpathSync(argv1);
  } catch {
    return false;
  }
  let self;
  try {
    self = fs.realpathSync(new URL(moduleUrl));
  } catch {
    return moduleUrl === pathToFileURL(real).href;
  }
  return self === real;
}
