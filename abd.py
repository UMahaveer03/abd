#!/usr/bin/env python3
"""
Automated Bug Discovery (ABD) - Complete Bug Hunting Application
Author: ABD Team
Description: A comprehensive automated bug hunting tool with 4 stages:
1. Preparation
2. Reconnaissance  
3. Vulnerability Identification
4. Exploitation
"""

import argparse
import sys
import os
import json
import datetime
from colorama import init, Fore, Style
from modules.preparation import PreparationStage
from modules.reconnaissance import ReconnaissanceStage
from modules.vulnerability import VulnerabilityStage
from modules.exploitation import ExploitationStage
from modules.utils import Logger, Config

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ABD:
    """Main ABD application class"""
    
    def __init__(self, target, config_file=None):
        self.target = target
        self.logger = Logger()
        self.config = Config(config_file)
        self.results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'stages': {}
        }
        
    def banner(self):
        """Display application banner"""
        banner = f"""
{Fore.CYAN}
 █████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗
███████║██████╔╝██║  ██║
██╔══██║██╔══██╗██║  ██║
██║  ██║██████╔╝██████╔╝
╚═╝  ╚═╝╚═════╝ ╚═════╝ 
{Style.RESET_ALL}
{Fore.GREEN}Automated Bug Discovery v1.0{Style.RESET_ALL}
{Fore.YELLOW}Target: {self.target}{Style.RESET_ALL}
{Fore.MAGENTA}═══════════════════════════════════{Style.RESET_ALL}
"""
        print(banner)
        
    def run_stage_1(self):
        """Stage 1: Preparation"""
        self.logger.info("Starting Stage 1: Preparation")
        stage = PreparationStage(self.target, self.config, self.logger)
        results = stage.execute()
        self.results['stages']['preparation'] = results
        return results
        
    def run_stage_2(self):
        """Stage 2: Reconnaissance"""
        self.logger.info("Starting Stage 2: Reconnaissance")
        stage = ReconnaissanceStage(self.target, self.config, self.logger)
        results = stage.execute()
        self.results['stages']['reconnaissance'] = results
        return results
        
    def run_stage_3(self):
        """Stage 3: Vulnerability Identification"""
        self.logger.info("Starting Stage 3: Vulnerability Identification")
        stage = VulnerabilityStage(self.target, self.config, self.logger)
        results = stage.execute()
        self.results['stages']['vulnerability'] = results
        return results
        
    def run_stage_4(self):
        """Stage 4: Exploitation"""
        self.logger.info("Starting Stage 4: Exploitation")
        stage = ExploitationStage(self.target, self.config, self.logger)
        results = stage.execute()
        self.results['stages']['exploitation'] = results
        return results
        
    def save_results(self):
        """Save results to output file"""
        output_dir = self.config.get('output_dir', 'output')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{output_dir}/abd_results_{self.target.replace('.', '_')}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        self.logger.success(f"Results saved to: {filename}")
        return filename
        
    def run_all_stages(self):
        """Execute all 4 stages of bug hunting"""
        try:
            self.banner()
            
            # Stage 1: Preparation
            prep_results = self.run_stage_1()
            if not prep_results.get('success', False):
                self.logger.error("Preparation stage failed. Aborting.")
                return False
                
            # Stage 2: Reconnaissance
            recon_results = self.run_stage_2()
            
            # Stage 3: Vulnerability Identification
            vuln_results = self.run_stage_3()
            
            # Stage 4: Exploitation
            exploit_results = self.run_stage_4()
            
            # Save results
            self.save_results()
            
            # Summary
            self.print_summary()
            
            return True
            
        except KeyboardInterrupt:
            self.logger.warning("Operation interrupted by user")
            return False
        except Exception as e:
            self.logger.error(f"An error occurred: {str(e)}")
            return False
            
    def print_summary(self):
        """Print execution summary"""
        print(f"\n{Fore.GREEN}═══ EXECUTION SUMMARY ═══{Style.RESET_ALL}")
        
        for stage_name, stage_results in self.results['stages'].items():
            status = "✓" if stage_results.get('success', False) else "✗"
            color = Fore.GREEN if stage_results.get('success', False) else Fore.RED
            print(f"{color}{status} {stage_name.upper()}: {stage_results.get('status', 'Unknown')}{Style.RESET_ALL}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Automated Bug Discovery - Complete Bug Hunting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 abd.py -t example.com
  python3 abd.py -t example.com -c config.json
  python3 abd.py -t example.com --stage preparation
        """
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Target domain or IP address')
    parser.add_argument('-c', '--config', 
                       help='Configuration file path')
    parser.add_argument('--stage', choices=['preparation', 'reconnaissance', 'vulnerability', 'exploitation'],
                       help='Run specific stage only')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
        
    # Create ABD instance
    abd = ABD(args.target, args.config)
    
    # Set verbose mode
    if args.verbose:
        abd.logger.set_verbose(True)
        
    # Run specific stage or all stages
    if args.stage:
        if args.stage == 'preparation':
            abd.run_stage_1()
        elif args.stage == 'reconnaissance':
            abd.run_stage_2()
        elif args.stage == 'vulnerability':
            abd.run_stage_3()
        elif args.stage == 'exploitation':
            abd.run_stage_4()
    else:
        abd.run_all_stages()


if __name__ == "__main__":
    main()