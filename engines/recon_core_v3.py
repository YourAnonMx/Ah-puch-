#!/usr/bin/env python3
"""Final target-aware Ah-Puch core adapter.

The architecture-v2 outer runner owns canonical HTTP status gating, all-origin
advanced consumers and every active industrial follow-up. The core industrial
stage is evidence-only and never opens a protocol connection. Dictionary
selection is delegated to the same class-aware local broker used by the outer
web fan-out.
"""
from __future__ import annotations

from pathlib import Path
from urllib.error import HTTPError, URLError

try:
    from . import dictionary_broker, recon_core_v2 as scoped
except ImportError:
    import dictionary_broker
    import recon_core_v2 as scoped


class FinalCoreRun(scoped.ScopedCoreRun):
    def dictionary_path(self) -> Path | None:
        """Use the canonical directory-class broker and family-level tier."""
        if not getattr(self, "use_dictionaries", True):
            return None
        requested = str(self.tool_value("dirsearch", "tier", self.wordlist_tier) or self.wordlist_tier).strip().lower()
        if requested not in dictionary_broker.VALID_TIERS:
            raise ValueError(f"unsupported directory dictionary tier: {requested}")
        configured = str(self.tool_value("dirsearch", "wordlist", "") or "").strip()
        if configured:
            info = dictionary_broker.explicit_info("directory", configured, tier=requested)
            return Path(str(info["path"])) if info.get("available") else None
        return dictionary_broker.resolve("directory", tier=requested)

    def run_range_surface(self) -> None:
        """Run the inherited range stage while preserving HTTP probe truth.

        The historical base range stage catches every ``urlopen`` exception and
        emits a final success event. Intercept the same calls in-place so no
        request is repeated: HTTP responses (including HTTPError negatives) are
        completed observations, while transport/internal exceptions remain
        errors. A corrective terminal event is appended only when needed.
        """
        counters = {"attempts": 0, "completed": 0, "transport_errors": 0, "internal_errors": 0}
        original_urlopen = scoped.base.urlopen

        def observed_urlopen(*args, **kwargs):
            counters["attempts"] += 1
            try:
                response = original_urlopen(*args, **kwargs)
            except HTTPError:
                counters["completed"] += 1
                raise
            except (URLError, TimeoutError, OSError):
                counters["transport_errors"] += 1
                raise
            except Exception:
                counters["internal_errors"] += 1
                raise
            counters["completed"] += 1
            return response

        scoped.base.urlopen = observed_urlopen
        try:
            super().run_range_surface()
        finally:
            scoped.base.urlopen = original_urlopen

        if self.target_kind != "range" or counters["attempts"] == 0:
            return
        errors = counters["transport_errors"] + counters["internal_errors"]
        if errors == 0:
            return
        status = "failed" if counters["completed"] == 0 else "partial"
        if status == "partial":
            self._range_path_partial = True
        self.event(
            "10-range",
            status,
            reason="range HTTP path probes did not all complete",
            attempts=counters["attempts"],
            completed=counters["completed"],
            transport_errors=counters["transport_errors"],
            internal_errors=counters["internal_errors"],
        )

    def finish(self) -> int:
        rc = super().finish()
        if rc != 0:
            return rc
        if getattr(self, "_range_path_partial", False):
            return 3
        return 0

    def optional_consumers(self) -> None:
        self.event(
            "11-consumers",
            "deferred",
            reason="outer Ah-Puch runtime owns target-origin advanced consumers",
        )

    def ics(self) -> None:
        """Build passive industrial indicators and defer all active contact."""
        stage = "09-ics"
        candidates: set[str] = set()
        protocols: set[str] = set()
        for path in self.output.rglob("*.txt"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lowered = text.lower()
            matched = {label for term, label in scoped.base.ICS_TERMS.items() if term in lowered}
            if not matched:
                continue
            observed = {
                value.rstrip(".,;:)]}")
                for value in scoped.base.URL_RE.findall(text)
                if self._allowed_url(value.rstrip(".,;:)]}"))
            }
            path_candidates = {
                value for value in observed
                if any(term in value.lower() for term in matched)
            } or observed
            if path.name.endswith(".urls.txt"):
                path_candidates.update(
                    line.strip()
                    for line in text.splitlines()
                    if line.strip().startswith(("http://", "https://"))
                    and self._allowed_url(line.strip())
                )
            if not path_candidates and self.base_url.startswith(("http://", "https://")) and self._allowed_url(self.base_url):
                path_candidates.add(self.base_url)
            candidates.update(path_candidates)
            for label in matched:
                for value in sorted(path_candidates):
                    protocols.add(f"{label}\t{value}\t{path.relative_to(self.output)}")

        scoped.base.write_lines(self.artifact(stage, "ics-candidates"), candidates)
        scoped.base.write_text(
            self.artifact(stage, "protocols"),
            "protocol\tcandidate\tsource\n" + "\n".join(sorted(protocols)) + ("\n" if protocols else ""),
        )
        for candidate in sorted(candidates)[:25]:
            self.alert("ICS candidate", candidate, stage)

        if self.intrusive:
            self.event(
                stage,
                "deferred",
                reason="canonical outer follow-up owns active industrial dispatch",
                probe_count=0,
                candidates=len(candidates),
            )
        else:
            self.event(stage, "skipped", reason="active industrial follow-up disabled", probe_count=0, candidates=len(candidates))


def main(argv: list[str] | None = None) -> int:
    import argparse
    import signal

    signal.signal(signal.SIGTERM, scoped.base.stop_active_process)
    signal.signal(signal.SIGINT, scoped.base.stop_active_process)
    parser = argparse.ArgumentParser(prog="recon_core_v3")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--profile", choices=("baseline", "full", "deep"), default="baseline")
    parser.add_argument("--run", default="full")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--intrusive", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--wordlist-tier", choices=("micro", "short", "long"), default="micro")
    parser.add_argument("--no-dictionaries", action="store_true")
    parser.add_argument("--range-ports", default="80,443,554,8000,8080,8554,502,102,20000,47808")
    parser.add_argument("--range-rate", type=int, default=500)
    parser.add_argument("--range-host-limit", type=int, default=256)
    parser.add_argument("--tool-option", action="append", default=[], metavar="TOOL.KEY=VALUE")
    parser.add_argument("--rebuild-saved", action="store_true")
    args = parser.parse_args(argv)
    if args.timeout < 1:
        parser.error("timeout must be positive")
    if args.range_rate < 1 or args.range_host_limit < 1:
        parser.error("range rate and host limit must be positive")
    try:
        tool_options = scoped.base.parse_tool_assignments(args.tool_option)
    except ValueError as exc:
        parser.error(str(exc))
    runner = FinalCoreRun(
        args.target,
        Path(args.output),
        args.profile,
        args.intrusive,
        args.timeout,
        args.wordlist_tier,
        args.range_ports,
        args.range_rate,
        args.range_host_limit,
        tool_options,
        use_dictionaries=not args.no_dictionaries,
    )
    return runner.rebuild_saved() if args.rebuild_saved else runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
