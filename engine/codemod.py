"""Source-level surgery for the fixer: extract one handler, replace it, validate
the proposed replacement, and load the patched app in isolation.

The patch unit is a single route handler (its `def` plus decorators). Working
at that granularity makes "minimal diff touching only that handler" structural
rather than a promise -- we literally splice one function back into the file and
leave everything else byte-for-byte unchanged. Validation then rejects any
replacement that renames the function, changes its route, or adds imports.
"""

from __future__ import annotations

import ast
import importlib.util
import uuid
from dataclasses import dataclass
from types import ModuleType


@dataclass
class HandlerBlock:
    name: str
    start_line: int          # 1-indexed, first decorator line
    end_line: int            # 1-indexed, inclusive
    routes: tuple[str, ...]  # route paths from decorators, e.g. ("/invoices/<int:invoice_id>",)
    text: str                # the exact source slice


_ROUTE_ATTRS = {"get", "post", "put", "patch", "delete", "route"}


def _routes_from_decorators(node: ast.AST) -> tuple[str, ...]:
    routes: list[str] = []
    for dec in getattr(node, "decorator_list", []):
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) \
                and dec.func.attr in _ROUTE_ATTRS and dec.args \
                and isinstance(dec.args[0], ast.Constant) \
                and isinstance(dec.args[0].value, str):
            routes.append(dec.args[0].value)
    return tuple(routes)


def extract_handler(source: str, name: str) -> HandlerBlock:
    """Return the source block (decorators + def) for a top-level handler."""
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
            end = node.end_lineno
            lines = source.splitlines(keepends=True)
            text = "".join(lines[start - 1:end])
            return HandlerBlock(name, start, end, _routes_from_decorators(node), text)
    raise ValueError(f"handler {name!r} not found in source")


def replace_handler(source: str, block: HandlerBlock, new_text: str) -> str:
    """Splice new_text in place of the given handler block, changing nothing else."""
    if not new_text.endswith("\n"):
        new_text += "\n"
    lines = source.splitlines(keepends=True)
    return "".join(lines[:block.start_line - 1] + [new_text] + lines[block.end_line:])


def validate_patch(new_text: str, expected_name: str,
                   expected_routes: tuple[str, ...]) -> tuple[bool, str]:
    """Reject anything that is not a minimal, same-shape replacement of the handler.

    Enforces: parses as Python; exactly one top-level function; same name; same
    route(s); no import statements anywhere in the block.
    """
    try:
        tree = ast.parse(new_text)
    except SyntaxError as exc:
        return False, f"proposed patch is not valid Python: {exc}"

    for sub in ast.walk(tree):
        if isinstance(sub, (ast.Import, ast.ImportFrom)):
            return False, "patch must not add import statements"

    funcs = [n for n in tree.body
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    others = [n for n in tree.body
              if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(funcs) != 1:
        return False, f"patch must define exactly one function, found {len(funcs)}"
    if others:
        kinds = ", ".join(type(n).__name__ for n in others)
        return False, f"patch must contain only the handler function, also found: {kinds}"

    fn = funcs[0]
    if fn.name != expected_name:
        return False, f"patch renamed the handler to {fn.name!r}; expected {expected_name!r}"

    routes = _routes_from_decorators(fn)
    if set(routes) != set(expected_routes):
        return False, (f"patch changed the route from {expected_routes} to {routes}; "
                       "the route must stay the same")

    return True, "ok"


def strip_code_fences(text: str) -> str:
    """Remove ```...``` fences if the model wrapped the handler in a code block."""
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        lines = lines[1:]                      # drop opening fence (``` or ```python)
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]                 # drop closing fence
        t = "\n".join(lines)
    return t.strip("\n") + "\n"


def load_app_module(app_path: str) -> ModuleType:
    """Import a patched target_app/app.py under a unique name (no sys.modules reuse)."""
    mod_name = "patched_app_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(mod_name, app_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load app from {app_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
