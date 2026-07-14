"""
Pipeline entry point
"""
import json
import argparse
import logging
import shutil
import subprocess
import time
from pathlib import Path
from datetime import datetime

from config import load_cve_config, list_cves, CVEConfig

from stages.collect import TrafficCollector
from stages.parse import parse_sysdig
from stages.segment import split_units
from stages.callstack import process_callstack
from stages.extract_code import extract_source_code
from stages.detect import create_detector
from stages.build import build_plugins

from stages.repair import RepairGenerator
from stages.whitelist import WhitelistFiller
from stages.validate import RepairValidator

logger = logging.getLogger(__name__)


STAGES = {
    0:  ("up",          "Start containers (docker compose up)"),
    1:  ("build",       "Build and install plugins (stack_tracer, syscall_filter, net_filter)"),
    2:  ("collect",     "Collect normal/malicious traffic (sysdig + locust)"),
    3:  ("parse",       "Convert sysdig logs to JSON"),
    4:  ("segment",     "Segment by request units"),
    5:  ("callstack",   "Extract call stacks"),
    6:  ("extract",     "Extract source code from container"),
    7:  ("detect",      "Anomaly detection (jaccard, ngram, etc.)"),
    8:  ("repair",      "Generate repair code (empty filter)"),
    9:  ("whitelist",   "Static analysis to populate whitelist"),
    10: ("validate",    "Restart container and validate repair"),
    11: ("down",        "Stop containers (docker compose down)"),
}


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )


def get_stages_help() -> str:
    lines = ["Stages:"]
    for num, (name, desc) in STAGES.items():
        lines.append(f"  {num:2}. {name:12} - {desc}")
    return "\n".join(lines)


def run_pipeline(cve: CVEConfig, stages: list[int], max_repairs: int = 1, validate_mode: str = "all",
                 normal_time: int = 60, malicious_time: int = 20, wait_time: int = 60, threshold: float = 0.5,
                 repair_mode: str = "filter", min_files: int = 10, whitelist_mode: str = "static", keep_repaired: bool = False,
                 algo: list[str] = None):
    env_dir = Path(f"cves/{cve.language}/{cve.cve_id}/env")

    timing = {}
    pipeline_start = time.time()

    for stage in stages:
        name, desc = STAGES.get(stage, ("unknown", "unknown stage"))
        logger.info("=" * 60)
        logger.info(f"Stage {stage}: {name}")
        logger.info("=" * 60)

        start = time.time()

        if stage == 0:
            subprocess.run(["docker", "compose", "up", "-d"], cwd=env_dir, check=True)

        elif stage == 1:
            build_plugins(cve)

        elif stage == 2:
            collector = TrafficCollector(cve, normal_time=normal_time, malicious_time=malicious_time)
            collector.run("both")

        elif stage == 3:
            parse_sysdig(cve)

        elif stage == 4:
            split_units(cve)

        elif stage == 5:
            whitelist_path = None
            if cve.use_whitelist:
                wl = cve.env_dir.parent / "whitelist.txt"
                if wl.exists():
                    whitelist_path = str(wl)
            process_callstack(cve, whitelist_file=whitelist_path)

        elif stage == 6:
            extract_source_code(cve)

        elif stage == 7:
            algo_list = algo if algo is not None else ["all"]
            detector = create_detector(algo_list)
            detector.run_detection(cve)

        elif stage == 8:
            generator = RepairGenerator(cve, repair_mode=repair_mode, whitelist_mode=whitelist_mode)
            generator.run(
                threshold=threshold,
                filter_irrelevant=cve.filter_irrelevant,
                backtrack_repair=cve.backtrack_repair,
                max_repairs=max_repairs,
            )

        elif stage == 9:
            filler = WhitelistFiller(cve, min_files=min_files)
            filler.run()

        elif stage == 10:
            validator = RepairValidator(cve)
            skip_normal = validate_mode == "abnormal"
            skip_malicious = validate_mode == "normal"
            validator.run(skip_normal=skip_normal, skip_malicious=skip_malicious, wait_time=wait_time, keep_repaired=keep_repaired)

        elif stage == 11:
            subprocess.run(["docker", "compose", "down", "-v"], cwd=env_dir, check=True)

        elapsed = time.time() - start
        logger.info(f"Stage {stage} completed in {elapsed:.1f}s")

        timing[f"stage_{stage}"] = {
            "duration": elapsed,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    if timing:
        pipeline_elapsed = time.time() - pipeline_start
        timing["total_duration"] = pipeline_elapsed

        timing_file = cve.data_dir / "timing.json"
        timing_file.parent.mkdir(parents=True, exist_ok=True)

        existing_timing = {}
        if timing_file.exists():
            try:
                with open(timing_file, 'r', encoding='utf-8') as f:
                    existing_timing = json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Invalid {timing_file}, overwriting with new data")
                existing_timing = {}

        merged_timing = {**existing_timing, **timing}

        with open(timing_file, 'w', encoding='utf-8') as f:
            json.dump(merged_timing, f, ensure_ascii=False, indent=2)

        logger.info(f"Timing saved to: {timing_file}")


def parse_stage_arg(stage_str: str) -> list[int]:
    """
    Parse stage argument.

    Supported formats:
        "3"     -> [3]
        "2-5"   -> [2, 3, 4, 5]
    """
    if "-" in stage_str:
        start, end = stage_str.split("-")
        return list(range(int(start), int(end) + 1))
    else:
        return [int(stage_str)]


def main():
    epilog = f"""
Examples:
  python main.py --cve CVE-2015-8562 --stage 0                    # Start containers
  python main.py --cve CVE-2015-8562 --stage 2-7                  # Collect and detect
  python main.py --cve CVE-2015-8562 --stage 7 --algo jaccard     # Detect with Jaccard only
  python main.py --cve CVE-2015-8562 --stage 7 --algo ngram file  # Detect with multiple algorithms
  python main.py --cve CVE-2015-8562 --stage 8                    # Generate repair code
  python main.py --cve CVE-2015-8562 --stage 9                    # Populate whitelist
  python main.py --cve CVE-2015-8562 --stage 10                   # Validate repair
  python main.py --cve CVE-2015-8562 --stage 8-10                 # Repair-whitelist-validate
  python main.py --cve CVE-2015-8562 --stage 11                   # Stop containers
  python main.py --cve CVE-2015-8562 --stage 0-11                 # Full pipeline
  python main.py --list                                           # List all CVEs

{get_stages_help()}
"""
    parser = argparse.ArgumentParser(
        description="Vulnerability Repair Pipeline",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cve", help="CVE ID (e.g. CVE-2015-8562)")
    parser.add_argument("--stage", help="Run specific stage (e.g. 3 or 0-10)")
    parser.add_argument("--list", action="store_true", help="List all available CVEs")
    parser.add_argument("--max-repairs", type=int, default=1, help="Max number of repairs (default: 1)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Stage 8 anomaly score threshold (default: 0.5)")
    parser.add_argument("--repair-mode", default="filter", choices=["filter", "direct", "direct_localization"],
                        help="Stage 8 repair mode: filter=filter-based, direct=direct logic repair, direct_localization=LLM localization+repair (default: filter)")
    parser.add_argument("--validate-mode", default="all", choices=["normal", "abnormal", "all"],
                        help="Stage 10 validation mode: normal=normal requests only, abnormal=malicious requests only, all=both (default: all)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Log level (default: INFO)")
    parser.add_argument("--normal-time", type=int, default=60,
                        help="Stage 2 normal traffic collection time in seconds (default: 60)")
    parser.add_argument("--malicious-time", type=int, default=20,
                        help="Stage 2 malicious traffic collection time in seconds (default: 20)")
    parser.add_argument("--wait-time", type=int, default=60,
                        help="Stage 10 wait time after container restart in seconds (default: 60)")
    parser.add_argument("--keep-repaired", action="store_true",
                        help="Stage 10 keep repaired state, do not restore original files (default: False)")
    parser.add_argument("--min-files", type=int, default=10,
                        help="Stage 9 minimum files to trigger directory compression (default: 10)")
    parser.add_argument("--whitelist-mode", default="static", choices=["static", "llm"],
                        help="Stage 8 whitelist generation: static=fill via Stage 9 static analysis, llm=LLM-generated (default: static)")
    parser.add_argument("--algo", nargs="+", default=["all"],
                        choices=["all", "jaccard", "ngram", "n_ips", "n_ports", "file", "proc", "internal"],
                        help="Stage 7 detection algorithms: all, jaccard, ngram, n_ips, n_ports, file, proc, internal (default: all, multiple allowed)")
    args = parser.parse_args()

    setup_logging(args.log_level)

    if args.list:
        print("Available CVEs:")
        for cve_id in list_cves():
            print(f"  {cve_id}")
        return

    if not args.cve:
        parser.print_help()
        return

    cve = load_cve_config(args.cve)

    if cve.manual_install:
        logger.warning(f"{args.cve} requires manual installation, please ensure installation steps are completed")

    stages = parse_stage_arg(args.stage) if args.stage else list(range(0, 12))

    if 0 in stages:
        data_dir = Path(f"data/{args.cve}")
        if data_dir.exists():
            shutil.rmtree(data_dir)
            logger.info(f"Cleaned data directory: {data_dir}")

    run_pipeline(cve, stages, max_repairs=args.max_repairs, validate_mode=args.validate_mode,
                 normal_time=args.normal_time, malicious_time=args.malicious_time, wait_time=args.wait_time,
                 threshold=args.threshold, repair_mode=args.repair_mode, min_files=args.min_files,
                 whitelist_mode=args.whitelist_mode, keep_repaired=args.keep_repaired, algo=args.algo)


if __name__ == "__main__":
    main()
