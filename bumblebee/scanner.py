"""
Scanner orchestrator.

Walks configured roots, dispatches matching files to ecosystem scanners,
applies time bounds, and emits NDJSON records through the Emitter.
"""

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional, Callable

from bumblebee.model import (
    ECOSYSTEM_NPM, ECOSYSTEM_PYPI, ECOSYSTEM_GO, ECOSYSTEM_RUBYGEMS,
    ECOSYSTEM_PACKAGIST, ECOSYSTEM_MCP, ECOSYSTEM_EDITOR_EXTENSION,
    ECOSYSTEM_BROWSER_EXTENSION, ECOSYSTEM_HOMEBREW, ECOSYSTEM_AGENT_SKILL,
    ROOT_KIND_UNKNOWN, Record, Finding, RECORD_TYPE_PACKAGE,
    RECORD_TYPE_FINDING, FINDING_TYPE_PACKAGE_EXPOSURE,
)
from bumblebee import walker
from bumblebee.emitter import Emitter
from bumblebee.exposure import Catalog


@dataclass
class Root:
    path: str = ""
    kind: str = ""

    def __post_init__(self):
        self.path = os.path.normpath(self.path)


@dataclass
class Config:
    profile: str = ""
    roots: list[Root] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    ecosystems: Optional[set[str]] = None  # None = all
    max_file_size: int = 5 * 1024 * 1024
    max_duration: float = 0  # seconds, 0 = unbounded
    concurrency: int = 4
    catalog: Optional[Catalog] = None
    findings_only: bool = False
    base_record: Record = field(default_factory=Record)
    emitter: Optional[Emitter] = None


@dataclass
class Result:
    files_considered: int = 0
    records_emitted: int = 0
    package_records_suppressed: int = 0
    findings_emitted: int = 0
    duplicates: int = 0
    diagnostics: int = 0
    timed_out: bool = False
    duration: float = 0.0


def run(ctx, cfg: Config) -> tuple[Result, Optional[Exception]]:
    """Execute one scan. Returns (Result, error)."""
    from bumblebee.ecosystems import (
        npm, pypi, gomod, rubygems, composer, mcp,
        bun, pnpm, yarn, editorext, browserext, homebrew, skills,
    )

    start = time.time()
    cfg.base_record.profile = cfg.profile

    root_kind_fn = _new_root_kind_lookup(cfg.roots)
    findings_emitted = 0
    findings_lock = threading.Lock()
    package_records_suppressed = 0
    suppressed_lock = threading.Lock()
    emit_error = None
    emit_error_lock = threading.Lock()

    def set_emit_error(err):
        nonlocal emit_error
        if err is None:
            return
        with emit_error_lock:
            if emit_error is None:
                emit_error = err

    emitter = cfg.emitter
    diag = emitter.diag if emitter else print

    # Build scanners
    npm_s = npm.Scanner(max_file_size=cfg.max_file_size)
    py_s = pypi.Scanner(max_file_size=cfg.max_file_size)
    pnpm_s = pnpm.Scanner(max_file_size=cfg.max_file_size)
    yarn_s = yarn.Scanner(max_file_size=cfg.max_file_size)
    bun_s = bun.Scanner(max_file_size=cfg.max_file_size)
    go_s = gomod.Scanner(max_file_size=cfg.max_file_size)
    rb_s = rubygems.Scanner(max_file_size=cfg.max_file_size)
    cmp_s = composer.Scanner(max_file_size=cfg.max_file_size)
    mcp_s = mcp.Scanner(max_file_size=cfg.max_file_size)
    skill_s = skills.Scanner(max_file_size=cfg.max_file_size)
    ext_s = editorext.Scanner(max_file_size=cfg.max_file_size)
    bx_s = browserext.Scanner(max_file_size=cfg.max_file_size)
    hb_s = homebrew.Scanner(max_file_size=cfg.max_file_size)

    # Job queue
    jobs = []
    jobs_lock = threading.Lock()

    def emit(r: Record):
        """Closure that handles dedup + optional finding emission."""
        nonlocal findings_emitted, package_records_suppressed

        # Set root_kind from the enclosing configured root
        rk = root_kind_fn(r.source_file)
        if rk != ROOT_KIND_UNKNOWN:
            r.root_kind = rk
        elif not r.root_kind:
            r.root_kind = ROOT_KIND_UNKNOWN

        if not r.profile:
            r.profile = cfg.profile

        r, written = emitter.observe_package(r)

        if cfg.findings_only:
            if written:
                with suppressed_lock:
                    package_records_suppressed += 1
        else:
            if written:
                err = emitter.emit_observed_package(r)
                if err:
                    set_emit_error(err)
                    return

        if not written:
            return

        if cfg.catalog:
            for m in cfg.catalog.match_all(r):
                entry, ver = m.entry, m.version
                f = Finding(
                    record_type=RECORD_TYPE_FINDING,
                    schema_version=cfg.base_record.schema_version,
                    scanner_name=cfg.base_record.scanner_name,
                    scanner_version=cfg.base_record.scanner_version,
                    run_id=cfg.base_record.run_id,
                    scan_time=cfg.base_record.scan_time,
                    endpoint=cfg.base_record.endpoint,
                    profile=cfg.profile,
                    finding_type=FINDING_TYPE_PACKAGE_EXPOSURE,
                    severity=entry.severity,
                    catalog_id=entry.id,
                    catalog_name=entry.name,
                    ecosystem=r.ecosystem,
                    package_name=r.package_name,
                    normalized_name=r.normalized_name,
                    version=r.version,
                    root_kind=r.root_kind,
                    project_path=r.project_path,
                    source_type=r.source_type,
                    source_file=r.source_file,
                    confidence=r.confidence,
                    evidence=f"exact name+version match (version={ver})",
                )
                err = emitter.emit_finding(f)
                if err is None:
                    with findings_lock:
                        findings_emitted += 1
                else:
                    set_emit_error(f"emit finding record: {err}")
                    break

    # Wire up emit and diag on each scanner
    for s in (npm_s, py_s, pnpm_s, yarn_s, bun_s, go_s, rb_s,
              cmp_s, mcp_s, skill_s, ext_s, bx_s, hb_s):
        s.emit = emit
        s.diag = diag

    # Check if ecosystem is enabled
    def enabled(ecosystem: str) -> bool:
        if cfg.ecosystems is None:
            return True
        return ecosystem in cfg.ecosystems

    # Collect jobs from walker
    collected_jobs = []

    def collect_jobs(full_path: str, basename: str):
        """Walker visitor — detect file type and queue a job."""
        nonlocal collected_jobs
        job = None

        # Skip credential-ish dotfiles
        if basename in (".env", ".envrc"):
            return

        # Dispatch by file type
        if enabled(ECOSYSTEM_NPM) and npm.is_lockfile(basename):
            job = ("npm-lock", full_path, "", "", "")
        elif enabled(ECOSYSTEM_NPM) and pnpm.is_lockfile(basename):
            job = ("pnpm-lock", full_path, "", "", "")
        elif enabled(ECOSYSTEM_NPM) and yarn.is_lockfile(basename):
            job = ("yarn-lock", full_path, "", "", "")
        elif enabled(ECOSYSTEM_NPM) and bun.is_text_lockfile(basename):
            job = ("bun-lock", full_path, "", "", "")
        elif enabled(ECOSYSTEM_NPM) and bun.is_binary_lockfile(basename):
            bun_s.note_binary_lockfile(full_path)
        elif enabled(ECOSYSTEM_GO) and gomod.is_go_sum(basename):
            job = ("go-sum", full_path, "", "", "")
        elif enabled(ECOSYSTEM_GO) and gomod.is_go_mod(basename):
            job = ("go-mod", full_path, "", "", "")
        elif enabled(ECOSYSTEM_RUBYGEMS) and rubygems.is_gemfile_lock(basename):
            job = ("rb-lock", full_path, "", "", "")
        elif enabled(ECOSYSTEM_RUBYGEMS) and rubygems.is_gemspec(basename):
            ok, gems_dir = rubygems.is_installed_gemspec(full_path)
            if ok:
                job = ("rb-spec", full_path, gems_dir, "", "")
        elif enabled(ECOSYSTEM_PACKAGIST) and composer.is_composer_lock(basename):
            job = ("composer-lock", full_path, "", "", "")
        elif enabled(ECOSYSTEM_PACKAGIST) and basename == "installed.json" and composer.is_installed_json(full_path):
            job = ("composer-installed", full_path, "", "", "")
        elif enabled(ECOSYSTEM_MCP) and mcp.is_known_mcp_config(basename):
            job = ("mcp-config", full_path, "", "", "")
        elif enabled(ECOSYSTEM_MCP) and basename == "settings.json" and mcp.is_gemini_settings_json(full_path):
            job = ("mcp-config", full_path, "", "", "")
        elif enabled(ECOSYSTEM_MCP) and mcp.is_claude_config_json(full_path):
            job = ("mcp-claude-config", full_path, "", "", "")
        elif enabled(ECOSYSTEM_AGENT_SKILL) and skills.is_known_lock_file(basename):
            job = ("skill-lock", full_path, "", "", "")
        elif enabled(ECOSYSTEM_BROWSER_EXTENSION) and basename == "manifest.json":
            ok, ext_id, ver_dir, prof_dir = bx_s.is_chromium_extension_manifest(full_path)
            if ok:
                job = ("chromium-ext", full_path, prof_dir, ext_id, ver_dir)
        elif enabled(ECOSYSTEM_BROWSER_EXTENSION) and basename == "extensions.json":
            if bx_s.is_firefox_extensions_json(full_path):
                job = ("firefox-ext", full_path, "", "", "")
        elif enabled(ECOSYSTEM_HOMEBREW) and basename == "INSTALL_RECEIPT.json":
            ok, name, version, cellar_dir = hb_s.is_formula_receipt(full_path)
            if ok:
                job = ("homebrew-formula", full_path, cellar_dir, name, version)
        elif enabled(ECOSYSTEM_HOMEBREW) and hb_s.looks_like_cask_metadata_marker(full_path):
            ok, token, version, caskroom_dir = hb_s.is_cask_metadata_marker(full_path)
            if ok:
                job = ("homebrew-cask", full_path, caskroom_dir, token, version)
        elif basename == "package.json":
            if enabled(ECOSYSTEM_EDITOR_EXTENSION):
                ok, ext_root, ext_dir = editorext.is_extension_package_json(full_path)
                if ok:
                    job = ("editor-ext", full_path, ext_root, ext_dir, "")
                    collected_jobs.append(job)
                    return
            if enabled(ECOSYSTEM_NPM):
                ok, proj, name, ver = pnpm.is_pnpm_store_package_json(full_path)
                if ok:
                    job = ("pnpm-pj", full_path, proj, name, ver)
                    collected_jobs.append(job)
                    return
                ok, proj = npm.is_node_modules_package_json(full_path)
                if ok:
                    job = ("npm-pj", full_path, proj, "", "")
        elif enabled(ECOSYSTEM_PYPI) and basename == "METADATA":
            ok, dir = pypi.is_dist_info_metadata(full_path)
            if ok:
                job = ("py-dist", full_path, dir, "", "")
        elif enabled(ECOSYSTEM_PYPI) and basename == "PKG-INFO":
            ok, dir = pypi.is_egg_info_pkg_info(full_path)
            if ok:
                job = ("py-egg", full_path, dir, "", "")

        if job:
            collected_jobs.append(job)

    # Walk all roots
    walk_excludes = list(walker.DEFAULT_EXCLUDES)
    walk_excludes.extend(cfg.excludes)

    def on_walk_error(path, err):
        level = "warn"
        if isinstance(err, (PermissionError, OSError)):
            eno = getattr(err, "errno", None)
            if eno in (13, 1):  # EACCES, EPERM
                level = "debug"
        emitter.diag(level, path, str(err))

    try:
        walker.walk(
            roots=[r.path for r in cfg.roots],
            excludes=walk_excludes,
            on_error=on_walk_error,
            visit=collect_jobs,
        )
    except Exception as e:
        emitter.diag("error", "", f"walker error: {e}")

    files_considered = len(collected_jobs)

    # Process jobs concurrently
    def process_job(job):
        kind, path, extra1, extra2, extra3 = job
        try:
            if kind == "npm-lock":
                npm_s.scan_lockfile(path, cfg.base_record)
            elif kind == "npm-pj":
                npm_s.scan_node_modules_package_json(path, extra1, cfg.base_record)
            elif kind == "py-dist":
                py_s.scan_dist_info(path, extra1, cfg.base_record)
            elif kind == "py-egg":
                py_s.scan_egg_info(path, extra1, cfg.base_record)
            elif kind == "pnpm-lock":
                pnpm_s.scan_lockfile(path, cfg.base_record)
            elif kind == "pnpm-pj":
                pnpm_s.scan_store_package_json(path, extra1, extra2, extra3, cfg.base_record)
            elif kind == "yarn-lock":
                yarn_s.scan_lockfile(path, cfg.base_record)
            elif kind == "bun-lock":
                bun_s.scan_text_lockfile(path, cfg.base_record)
            elif kind == "go-sum":
                go_s.scan_go_sum(path, cfg.base_record)
            elif kind == "go-mod":
                go_s.scan_go_mod(path, cfg.base_record)
            elif kind == "rb-lock":
                rb_s.scan_gemfile_lock(path, cfg.base_record)
            elif kind == "rb-spec":
                rb_s.scan_gemspec(path, extra1, cfg.base_record)
            elif kind == "composer-lock":
                cmp_s.scan_composer_lock(path, cfg.base_record)
            elif kind == "composer-installed":
                cmp_s.scan_installed_json(path, cfg.base_record)
            elif kind == "mcp-config":
                mcp_s.scan_config(path, cfg.base_record)
            elif kind == "mcp-claude-config":
                mcp_s.scan_claude_config(path, cfg.base_record)
            elif kind == "skill-lock":
                skill_s.scan_lock_file(path, cfg.base_record)
            elif kind == "editor-ext":
                ext_s.scan_extension(path, extra1, extra2, cfg.base_record)
            elif kind == "chromium-ext":
                bx_s.scan_chromium_extension(path, extra2, extra3, extra1, cfg.base_record)
            elif kind == "firefox-ext":
                bx_s.scan_firefox_extensions(path, cfg.base_record)
            elif kind == "homebrew-formula":
                hb_s.scan_formula_receipt(path, extra2, extra3, extra1, cfg.base_record)
            elif kind == "homebrew-cask":
                hb_s.scan_cask_metadata(path, extra2, extra3, extra1, cfg.base_record)
        except Exception as e:
            emitter.diag("error", path, str(e))

    # Process jobs with thread pool
    with ThreadPoolExecutor(max_workers=cfg.concurrency) as executor:
        futures = [executor.submit(process_job, j) for j in collected_jobs]
        for f in futures:
            try:
                f.result()
            except Exception as e:
                pass  # already handled in process_job

    duration = time.time() - start
    timed_out = False
    if cfg.max_duration > 0 and duration > cfg.max_duration:
        timed_out = True

    result = Result(
        files_considered=files_considered,
        records_emitted=emitter.records_emitted if emitter else 0,
        findings_emitted=findings_emitted,
        duplicates=emitter.duplicates if emitter else 0,
        diagnostics=emitter.diagnostics_count if emitter else 0,
        duration=duration,
        timed_out=timed_out,
    )
    with suppressed_lock:
        result.package_records_suppressed = package_records_suppressed

    return result, emit_error


def _new_root_kind_lookup(roots: list[Root]) -> Callable[[str], str]:
    """Build a lookup function that maps a file path to its root kind."""
    cleaned = []
    for r in roots:
        if not r.path:
            continue
        try:
            p = os.path.abspath(r.path)
        except ValueError:
            p = r.path
        cleaned.append(Root(path=os.path.normpath(p), kind=r.kind))

    def lookup(path: str) -> str:
        if not path:
            return ROOT_KIND_UNKNOWN
        try:
            abs_path = os.path.normpath(os.path.abspath(path))
        except ValueError:
            abs_path = os.path.normpath(path)
        best_len = -1
        best = ROOT_KIND_UNKNOWN
        for r in cleaned:
            if abs_path == r.path or abs_path.startswith(r.path + os.sep):
                if len(r.path) > best_len:
                    best_len = len(r.path)
                    best = r.kind
        return best

    return lookup
