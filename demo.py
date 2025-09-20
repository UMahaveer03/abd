#!/usr/bin/env python3
"""
ABD Example Usage Script
Demonstrates different ways to use the Automated Bug Discovery tool
"""

import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and display results"""
    print(f"\n{'='*60}")
    print(f"🔹 {description}")
    print(f"{'='*60}")
    print(f"Command: {cmd}")
    print("-" * 60)
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.stdout:
            print("Output:")
            print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
        print(f"Exit code: {result.returncode}")
    except subprocess.TimeoutExpired:
        print("Command timed out after 30 seconds")
    except Exception as e:
        print(f"Error running command: {e}")

def main():
    """Main demonstration function"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                   ABD DEMONSTRATION SCRIPT                   ║
    ║              Automated Bug Discovery Examples                ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Check if ABD is available
    if not os.path.exists("abd.py"):
        print("❌ Error: abd.py not found in current directory")
        print("Please run this script from the ABD directory")
        return
    
    # Example 1: Help and version
    run_command("python3 abd.py --help", "Display help information")
    
    # Example 2: Single stage execution
    run_command("python3 abd.py -t example.com --stage preparation", 
                "Run only the preparation stage")
    
    # Example 3: Show configuration
    if os.path.exists("config.json"):
        print(f"\n{'='*60}")
        print("🔹 Configuration file content")
        print(f"{'='*60}")
        with open("config.json", "r") as f:
            print(f.read())
    
    # Example 4: Show output structure
    if os.path.exists("output"):
        print(f"\n{'='*60}")
        print("🔹 Output directory structure")
        print(f"{'='*60}")
        run_command("find output -type f -name '*.json' | head -5", 
                    "Generated assessment files")
    
    # Example 5: Show wordlists
    if os.path.exists("wordlists"):
        print(f"\n{'='*60}")
        print("🔹 Available wordlists")
        print(f"{'='*60}")
        run_command("ls -la wordlists/ && echo '--- First 10 subdomains ---' && head -10 wordlists/subdomains.txt", 
                    "Wordlist contents")
    
    print(f"\n{'='*60}")
    print("🎯 Additional Examples")
    print(f"{'='*60}")
    
    examples = [
        "# Complete assessment with verbose output",
        "python3 abd.py -t target.com -v",
        "",
        "# Custom configuration file",
        "python3 abd.py -t target.com -c custom_config.json",
        "",
        "# Run specific stages in sequence",
        "python3 abd.py -t target.com --stage reconnaissance",
        "python3 abd.py -t target.com --stage vulnerability",
        "",
        "# Quick reconnaissance scan",
        "python3 abd.py -t target.com --stage reconnaissance -v",
        "",
        "# Full automated assessment",
        "python3 abd.py -t target.com",
    ]
    
    for example in examples:
        print(example)
    
    print(f"\n{'='*60}")
    print("📊 Report Types Generated")
    print(f"{'='*60}")
    
    reports = [
        "• assessment_scope.json - Assessment scope and limitations",
        "• exploitation_report_*.json - Technical findings (JSON)",
        "• exploitation_report_*.html - Visual report (HTML)", 
        "• executive_summary_*.txt - Executive summary",
        "• abd.log - Detailed execution log"
    ]
    
    for report in reports:
        print(report)
    
    print(f"\n{'='*60}")
    print("⚠️  Security Notice")
    print(f"{'='*60}")
    print("""
    ABD is designed for authorized security testing only.
    
    ✅ DO:
    • Test systems you own or have explicit permission to test
    • Follow responsible disclosure practices
    • Respect rate limits and server resources
    • Comply with local laws and regulations
    
    ❌ DON'T:
    • Test systems without authorization
    • Use for malicious purposes
    • Ignore terms of service
    • Perform destructive testing
    """)
    
    print("\n🚀 Happy bug hunting with ABD!")

if __name__ == "__main__":
    main()