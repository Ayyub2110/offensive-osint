"""
Main entry point for the AI Offensive OSINT application.

This module provides a CLI interface for running the complete OSINT workflow,
coordinating multiple agents to perform automated security reconnaissance,
attack surface mapping, and target prioritization.

USAGE:
    python main.py --domain targetcorp.com
    python main.py --username johndoe --domain targetcorp.com
    python main.py --domain targetcorp.com --name "John Doe" --output report.json
"""

import asyncio
import argparse
import json
import sys
import io
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from graph.osint_langgraph import run_osint_workflow
from config import load_config


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="AI Offensive OSINT - Automated reconnaissance and attack surface mapping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Domain reconnaissance only
  python main.py --domain targetcorp.com
  
  # Full user + domain reconnaissance
  python main.py --username johndoe --domain targetcorp.com
  
  # With target name for email inference
  python main.py --username johndoe --name "John Doe" --domain targetcorp.com
  
  # Specify output files
  python main.py --domain targetcorp.com --output results.json --markdown report.md
  
  # Custom target URL
  python main.py --domain targetcorp.com --url https://app.targetcorp.com
        """,
    )

    # Target specification
    parser.add_argument(
        "-u",
        "--username",
        help="Target username for correlation across platforms",
        type=str,
    )

    parser.add_argument(
        "-n",
        "--name",
        help="Target full name for email pattern inference (e.g., 'John Doe')",
        type=str,
    )

    parser.add_argument(
        "-d",
        "--domain",
        help="Target domain for asset discovery and tech fingerprinting",
        type=str,
        required=True,
    )

    parser.add_argument(
        "--url",
        help="Specific target URL for fingerprinting (default: https://<domain>)",
        type=str,
    )

    # Output options
    parser.add_argument(
        "-o",
        "--output",
        help="Output JSON file path (default: osint_report_<timestamp>.json)",
        type=str,
    )

    parser.add_argument(
        "-m",
        "--markdown",
        help="Output Markdown report file path (default: osint_report_<timestamp>.md)",
        type=str,
    )

    # Workflow options
    parser.add_argument(
        "--max-iterations",
        help="Maximum reconnaissance iterations (default: 3)",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--no-output",
        help="Do not save output files (only print to console)",
        action="store_true",
    )

    return parser.parse_args()


def generate_markdown_report(state: Dict[str, Any]) -> str:
    """
    Generate a pentester-friendly Markdown report.

    Args:
        state: Final workflow state

    Returns:
        Markdown formatted report
    """
    lines = []

    # Header
    lines.append("# OSINT Reconnaissance Report")
    lines.append("")
    lines.append(
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    lines.append(f"**Target Domain:** {state.get('domain', 'N/A')}")
    if state.get("username"):
        lines.append(f"**Target Username:** {state.get('username')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")

    # Count findings
    total_assets = 0
    critical_targets = 0
    high_targets = 0

    if state.get("asset_discovery"):
        total_assets = state["asset_discovery"].get("total_assets", 0)

    if state.get("attack_surface_prioritization"):
        summary = state["attack_surface_prioritization"].get("summary", {})
        critical_targets = summary.get("critical", 0)
        high_targets = summary.get("high", 0)

    lines.append(f"- **Total Assets Discovered:** {total_assets}")
    lines.append(f"- **Critical Priority Targets:** {critical_targets}")
    lines.append(f"- **High Priority Targets:** {high_targets}")
    lines.append("")

    # Username Correlation
    if state.get("username_correlation"):
        lines.append("## Username Correlation")
        lines.append("")
        uc = state["username_correlation"]
        summary = uc.get("summary", {})

        lines.append(f"**Username:** {uc.get('username', 'N/A')}")
        lines.append(
            f"**Platforms Found:** {summary.get('exists', 0)}/{summary.get('total', 0)}"
        )
        lines.append("")

        if summary.get("platforms_found"):
            lines.append("**Active Platforms:**")
            for platform in summary["platforms_found"]:
                lines.append(f"- {platform.title()}")
            lines.append("")

    # Email Patterns
    if state.get("email_patterns"):
        lines.append("## Email Pattern Inference")
        lines.append("")
        ep = state["email_patterns"]

        lines.append(f"**Total Patterns Generated:** {ep.get('total_patterns', 0)}")
        lines.append("")

        # Domain validation
        domain_val = ep.get("domain_validation")
        if domain_val:
            lines.append(
                f"**Domain Valid:** {'Yes' if domain_val.get('is_valid') else 'No'}"
            )
            lines.append(
                f"**MX Records:** {'Yes' if domain_val.get('has_mx') else 'No'}"
            )
            if domain_val.get("smtp_servers"):
                lines.append(
                    f"**SMTP Servers:** {', '.join(domain_val['smtp_servers'])}"
                )
            lines.append("")

        # Top email patterns
        patterns = ep.get("patterns", [])[:10]
        if patterns:
            lines.append("**Top 10 Probable Emails:**")
            for i, pattern in enumerate(patterns, 1):
                lines.append(
                    f"{i}. `{pattern['email']}` (confidence: {pattern['confidence']})"
                )
            lines.append("")

    # Asset Discovery
    if state.get("asset_discovery"):
        lines.append("## Asset Discovery")
        lines.append("")
        ad = state["asset_discovery"]

        lines.append(f"**Total Assets:** {ad.get('total_assets', 0)}")
        lines.append("")

        summary = ad.get("summary", {})
        if summary:
            lines.append("**Asset Breakdown:**")
            for asset_type, count in summary.items():
                lines.append(f"- {asset_type.title()}: {count}")
            lines.append("")

        # Highlight sensitive assets
        categorized = ad.get("categorized", {})
        sensitive = categorized.get("sensitive_file", [])
        if sensitive:
            lines.append("### Sensitive Files Found")
            lines.append("")
            for asset in sensitive[:10]:
                status = asset.get("status_code", "N/A")
                lines.append(f"- `{asset['asset']}` (Status: {status})")
            lines.append("")

    # Technology Fingerprint
    if state.get("tech_fingerprint"):
        lines.append("## Technology Stack")
        lines.append("")
        tf = state["tech_fingerprint"]

        # Web server
        web_server = tf.get("web_server", {})
        if web_server.get("type"):
            version = web_server.get("version", "unknown")
            lines.append(f"**Web Server:** {web_server['type']} {version}")

        # Backend
        backend = tf.get("backend", {})
        primary = backend.get("primary")
        if primary:
            lines.append(
                f"**Backend:** {primary.get('technology', 'unknown')} (confidence: {primary.get('confidence', 0)}%)"
            )

        # CMS
        cms = tf.get("cms", {})
        cms_primary = cms.get("primary")
        if cms_primary:
            cms_name = cms_primary.get("cms", "unknown")
            cms_version = cms_primary.get("version", "unknown")
            lines.append(f"**CMS:** {cms_name} {cms_version}")

        # Security
        security = tf.get("security", {})
        waf_cdn = security.get("waf_cdn", {})
        if waf_cdn.get("has_waf"):
            detected = waf_cdn.get("detected", [])
            if detected:
                waf_name = detected[0].get("name", "unknown")
                lines.append(f"**WAF Detected:** {waf_name}")
        else:
            lines.append("**WAF Detected:** None ⚠️")

        sec_headers = security.get("security_headers", {})
        if sec_headers:
            lines.append(
                f"**Security Header Score:** {sec_headers.get('score', 0)}/100"
            )

        lines.append("")

    # Attack Surface Prioritization
    if state.get("attack_surface_prioritization"):
        lines.append("## Attack Surface Prioritization")
        lines.append("")
        asp = state["attack_surface_prioritization"]

        # Top targets
        top_targets = asp.get("top_targets", [])[:10]
        if top_targets:
            lines.append("### Top 10 Priority Targets")
            lines.append("")

            for i, target in enumerate(top_targets, 1):
                asset = target.get("asset", "unknown")
                score = target.get("total_score", 0)
                priority = target.get("priority_level", "unknown").upper()

                lines.append(f"#### {i}. {asset}")
                lines.append(f"**Score:** {score}/100 | **Priority:** {priority}")
                lines.append("")

                # Scoring factors
                factors = target.get("scoring_factors", [])[:3]
                if factors:
                    lines.append("**Key Factors:**")
                    for factor in factors:
                        lines.append(
                            f"- {factor['description']} (score: {factor['weighted_score']:.1f})"
                        )
                    lines.append("")

                # Attack recommendations
                attacks = target.get("recommended_attacks", [])[:5]
                if attacks:
                    lines.append("**Recommended Attacks:**")
                    for attack in attacks:
                        lines.append(f"- {attack}")
                    lines.append("")

    # LLM Attack Advisory
    if state.get("attack_advisory"):
        lines.append("## LLM Attack Advisory")
        lines.append("")
        lines.append(
            "*Strategic attack path recommendations from AI-powered red team advisor*"
        )
        lines.append("")

        advisory = state["attack_advisory"]

        # Executive summary
        exec_summary = advisory.get("executive_summary", "")
        if exec_summary:
            lines.append("### Executive Assessment")
            lines.append("")
            lines.append(exec_summary)
            lines.append("")

        # Intelligence quality
        quality = advisory.get("intelligence_quality", "unknown")
        model = advisory.get("model_used", "unknown")
        lines.append(f"**Intelligence Quality:** {quality.title()}")
        lines.append(f"**Analysis Model:** {model}")
        lines.append("")

        # Attack paths
        attack_paths = advisory.get("attack_paths", [])
        if attack_paths:
            lines.append(
                f"### Recommended Attack Paths ({len(attack_paths)} identified)"
            )
            lines.append("")

            for i, path in enumerate(attack_paths, 1):
                name = path.get("name", "Unknown Attack")
                category = path.get("category", "unknown")
                description = path.get("description", "")
                success_prob = path.get("success_probability", "unknown").upper()
                detection = path.get("detection_likelihood", "unknown").upper()
                effort = path.get("estimated_effort", "unknown")

                lines.append(f"#### {i}. {name}")
                lines.append(
                    f"**Category:** {category} | **Success:** {success_prob} | **Detection Risk:** {detection} | **Effort:** {effort}"
                )
                lines.append("")

                if description:
                    lines.append(f"**Description:** {description}")
                    lines.append("")

                # Steps
                steps = path.get("steps", [])
                if steps:
                    lines.append("**Execution Steps:**")
                    for step_num, step in enumerate(steps, 1):
                        lines.append(f"{step_num}. {step}")
                    lines.append("")

                # Tools required
                tools = path.get("tools_required", [])
                if tools:
                    lines.append(f"**Tools Required:** {', '.join(tools)}")
                    lines.append("")

                # Prerequisites
                prereqs = path.get("prerequisites", [])
                if prereqs:
                    lines.append(f"**Prerequisites:** {', '.join(prereqs)}")
                    lines.append("")

                # Impact
                impact = path.get("impact", "")
                if impact:
                    lines.append(f"**Expected Impact:** {impact}")
                    lines.append("")

                # Intelligence basis
                basis = path.get("intelligence_basis", "")
                if basis:
                    lines.append(f"*Intelligence Basis: {basis}*")
                    lines.append("")

        # Recommended order
        recommended_order = advisory.get("recommended_order", [])
        if recommended_order:
            lines.append("### Recommended Execution Order")
            lines.append("")
            for i, attack_name in enumerate(recommended_order, 1):
                lines.append(f"{i}. {attack_name}")
            lines.append("")

        # Defense evasion
        evasion_tips = advisory.get("defense_evasion_tips", [])
        if evasion_tips:
            lines.append("### Defense Evasion & OPSEC Considerations")
            lines.append("")
            for tip in evasion_tips:
                lines.append(f"- {tip}")
            lines.append("")

    # Recon Decision
    if state.get("recon_decision"):
        lines.append("## Reconnaissance Decision")
        lines.append("")
        rd = state["recon_decision"]

        lines.append(f"**Decision:** {rd.get('decision', 'unknown').upper()}")
        lines.append(f"**Confidence:** {rd.get('confidence', 0):.2f}")
        lines.append(f"**Reason:** {rd.get('primary_reason', 'N/A')}")
        lines.append("")

    # Errors
    errors = state.get("errors", [])
    if errors:
        lines.append("## Errors Encountered")
        lines.append("")
        for error in errors:
            lines.append(f"- {error}")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append("*Report generated by AI Offensive OSINT Framework*")
    lines.append("")

    return "\n".join(lines)


def print_summary_report(state: Dict[str, Any]) -> None:
    """
    Print a summary report to console.

    Args:
        state: Final workflow state
    """
    print("\n" + "=" * 70)
    print("FINAL INTELLIGENCE REPORT")
    print("=" * 70)

    # Asset summary
    if state.get("asset_discovery"):
        ad = state["asset_discovery"]
        print(f"\n📊 Assets Discovered: {ad.get('total_assets', 0)}")

        summary = ad.get("summary", {})
        for asset_type, count in summary.items():
            print(f"   - {asset_type}: {count}")

    # Priority targets
    if state.get("attack_surface_prioritization"):
        asp = state["attack_surface_prioritization"]
        summary = asp.get("summary", {})

        print(f"\n🎯 Priority Targets:")
        print(f"   - Critical: {summary.get('critical', 0)}")
        print(f"   - High: {summary.get('high', 0)}")
        print(f"   - Medium: {summary.get('medium', 0)}")

        # Show top 3 targets
        top_targets = asp.get("top_targets", [])[:3]
        if top_targets:
            print(f"\n🔥 Top 3 Targets:")
            for i, target in enumerate(top_targets, 1):
                print(f"   {i}. {target['asset']}")
                print(
                    f"      Score: {target['total_score']:.1f}/100 | Priority: {target['priority_level'].upper()}"
                )

    # Attack Advisory
    if state.get("attack_advisory"):
        advisory = state["attack_advisory"]
        attack_paths = advisory.get("attack_paths", [])

        if attack_paths:
            print(f"\n⚔️  Strategic Attack Paths: {len(attack_paths)} recommended")

            # Show top 3 attack paths
            for i, path in enumerate(attack_paths[:3], 1):
                name = path.get("name", "Unknown")
                success = path.get("success_probability", "unknown").upper()
                category = path.get("category", "unknown")
                print(f"   {i}. {name}")
                print(f"      Category: {category} | Success Probability: {success}")

    # Email patterns
    if state.get("email_patterns"):
        ep = state["email_patterns"]
        print(f"\n📧 Email Patterns Generated: {ep.get('total_patterns', 0)}")

        # Show top 5 emails
        patterns = ep.get("patterns", [])[:5]
        if patterns:
            print("   Top 5 probable emails:")
            for pattern in patterns:
                print(f"   - {pattern['email']} (confidence: {pattern['confidence']})")

    # Username correlation
    if state.get("username_correlation"):
        uc = state["username_correlation"]
        summary = uc.get("summary", {})
        platforms = summary.get("platforms_found", [])

        if platforms:
            print(f"\n👤 Username found on {len(platforms)} platforms:")
            for platform in platforms[:5]:
                print(f"   - {platform.title()}")

    # Errors
    errors = state.get("errors", [])
    if errors:
        print(f"\n⚠️  Errors: {len(errors)}")
        for error in errors[:3]:
            print(f"   - {error}")

    print("\n" + "=" * 70)


async def main() -> None:
    """
    Main execution function for the OSINT application.

    Workflow:
        1. Parse CLI arguments
        2. Load configuration
        3. Execute OSINT workflow
        4. Generate and save reports
        5. Display summary
    """
    # Parse arguments
    args = parse_arguments()

    # Load configuration (for future use with API keys, etc.)
    try:
        config = load_config()
    except Exception as e:
        print(f"Warning: Could not load config: {e}")
        config = {}

    # Prepare target URL
    target_url = args.url
    if not target_url and args.domain:
        target_url = f"https://{args.domain}"

    # Execute workflow
    try:
        final_state = await run_osint_workflow(
            username=args.username,
            target_name=args.name,
            domain=args.domain,
            target_url=target_url,
            max_iterations=args.max_iterations,
        )
    except Exception as e:
        print(f"\n[FATAL ERROR] Workflow execution failed: {e}")
        sys.exit(1)

    # Print console summary
    print_summary_report(final_state)

    # Save outputs if requested
    if not args.no_output:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        # JSON output
        json_file = args.output or f"osint_report_{timestamp}.json"
        json_path = Path(json_file)

        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(final_state, f, indent=2, default=str)
            print(f"\n💾 JSON report saved: {json_path.absolute()}")
        except Exception as e:
            print(f"\n❌ Failed to save JSON report: {e}")

        # Markdown output
        md_file = args.markdown or f"osint_report_{timestamp}.md"
        md_path = Path(md_file)

        try:
            markdown_report = generate_markdown_report(final_state)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(markdown_report)
            print(f"📄 Markdown report saved: {md_path.absolute()}")
        except Exception as e:
            print(f"❌ Failed to save Markdown report: {e}")

    print("\n✅ OSINT workflow completed successfully!\n")


if __name__ == "__main__":
    asyncio.run(main())
