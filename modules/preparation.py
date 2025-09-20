"""
Stage 1: Preparation
- Target validation and scope definition
- Tool availability checks
- Configuration setup
- Output directory creation
"""

import os
import sys
import subprocess
import socket
from datetime import datetime
from .utils import NetworkUtils, FileUtils


class PreparationStage:
    """Stage 1: Preparation"""
    
    def __init__(self, target, config, logger):
        self.target = target
        self.config = config
        self.logger = logger
        self.results = {
            'stage': 'preparation',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'status': 'Starting preparation...',
            'target_info': {},
            'environment_check': {},
            'setup_status': {}
        }
        
    def validate_target(self):
        """Validate the target domain or IP"""
        self.logger.info("Validating target...")
        
        target_info = {
            'target': self.target,
            'type': None,
            'ip_address': None,
            'is_reachable': False
        }
        
        # Determine if target is IP or domain
        if NetworkUtils.is_valid_ip(self.target):
            target_info['type'] = 'ip'
            target_info['ip_address'] = self.target
        elif NetworkUtils.is_valid_domain(self.target):
            target_info['type'] = 'domain'
            ip = NetworkUtils.resolve_domain(self.target)
            if ip:
                target_info['ip_address'] = ip
                target_info['is_reachable'] = True
            else:
                self.logger.warning(f"Could not resolve domain: {self.target}")
        else:
            self.logger.error(f"Invalid target format: {self.target}")
            return False
            
        # Test basic connectivity
        if target_info['ip_address']:
            try:
                # Try to connect to common ports
                for port in [80, 443]:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((target_info['ip_address'], port))
                    if result == 0:
                        target_info['is_reachable'] = True
                        break
                    sock.close()
            except Exception as e:
                self.logger.debug(f"Connectivity test error: {e}")
                
        self.results['target_info'] = target_info
        
        if target_info['type']:
            self.logger.success(f"Target validated: {self.target} ({target_info['type']})")
            return True
        else:
            self.logger.error("Target validation failed")
            return False
            
    def check_environment(self):
        """Check system environment and tool availability"""
        self.logger.info("Checking environment and tools...")
        
        env_check = {
            'python_version': sys.version,
            'platform': sys.platform,
            'tools': {},
            'permissions': {},
            'dependencies': {}
        }
        
        # Check for common security tools
        tools_to_check = [
            'nmap', 'curl', 'wget', 'dig', 'nslookup', 'ping', 'telnet'
        ]
        
        for tool in tools_to_check:
            try:
                result = subprocess.run(['which', tool], 
                                      capture_output=True, text=True, timeout=5)
                env_check['tools'][tool] = {
                    'available': result.returncode == 0,
                    'path': result.stdout.strip() if result.returncode == 0 else None
                }
            except Exception as e:
                env_check['tools'][tool] = {
                    'available': False,
                    'error': str(e)
                }
                
        # Check Python dependencies
        required_modules = ['requests', 'socket', 'subprocess', 'threading', 'json']
        for module in required_modules:
            try:
                __import__(module)
                env_check['dependencies'][module] = {'available': True}
            except ImportError:
                env_check['dependencies'][module] = {'available': False}
                
        # Check write permissions
        try:
            test_file = 'test_permissions.tmp'
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            env_check['permissions']['write'] = True
        except Exception:
            env_check['permissions']['write'] = False
            
        self.results['environment_check'] = env_check
        
        # Count available tools
        available_tools = sum(1 for tool_info in env_check['tools'].values() 
                            if tool_info.get('available', False))
        self.logger.info(f"Found {available_tools}/{len(tools_to_check)} security tools")
        
        return True
        
    def setup_workspace(self):
        """Setup working directories and files"""
        self.logger.info("Setting up workspace...")
        
        setup_status = {
            'directories': {},
            'wordlists': {},
            'config': {}
        }
        
        # Create output directory
        output_dir = self.config.get('output_dir', 'output')
        try:
            os.makedirs(output_dir, exist_ok=True)
            setup_status['directories']['output'] = {
                'path': output_dir,
                'created': True
            }
            self.logger.debug(f"Output directory created: {output_dir}")
        except Exception as e:
            setup_status['directories']['output'] = {
                'path': output_dir,
                'created': False,
                'error': str(e)
            }
            self.logger.error(f"Failed to create output directory: {e}")
            
        # Create target-specific subdirectory
        target_dir = os.path.join(output_dir, self.target.replace('.', '_'))
        try:
            os.makedirs(target_dir, exist_ok=True)
            setup_status['directories']['target'] = {
                'path': target_dir,
                'created': True
            }
            self.logger.debug(f"Target directory created: {target_dir}")
        except Exception as e:
            setup_status['directories']['target'] = {
                'path': target_dir,
                'created': False,
                'error': str(e)
            }
            
        # Setup wordlists
        try:
            FileUtils.create_wordlist_if_not_exists()
            setup_status['wordlists']['subdomains'] = {
                'path': 'wordlists/subdomains.txt',
                'created': True
            }
            self.logger.debug("Wordlists setup completed")
        except Exception as e:
            setup_status['wordlists']['subdomains'] = {
                'path': 'wordlists/subdomains.txt',
                'created': False,
                'error': str(e)
            }
            
        # Validate configuration
        required_config = ['timeout', 'threads', 'user_agent']
        for key in required_config:
            value = self.config.get(key)
            setup_status['config'][key] = {
                'value': value,
                'set': value is not None
            }
            
        self.results['setup_status'] = setup_status
        return True
        
    def generate_scope_definition(self):
        """Generate scope definition for the assessment"""
        self.logger.info("Generating assessment scope...")
        
        scope = {
            'target': self.target,
            'target_type': self.results['target_info'].get('type'),
            'ip_address': self.results['target_info'].get('ip_address'),
            'timestamp': datetime.now().isoformat(),
            'assessment_id': f"ABD_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'stages_to_run': ['reconnaissance', 'vulnerability', 'exploitation'],
            'tools_available': [],
            'limitations': [
                'Only automated testing',
                'No destructive operations',
                'Respect rate limits',
                'Stop on detection of active defenses'
            ]
        }
        
        # Add available tools to scope
        env_check = self.results.get('environment_check', {})
        for tool, info in env_check.get('tools', {}).items():
            if info.get('available', False):
                scope['tools_available'].append(tool)
                
        self.results['scope'] = scope
        
        # Save scope to file
        output_dir = self.config.get('output_dir', 'output')
        target_dir = os.path.join(output_dir, self.target.replace('.', '_'))
        scope_file = os.path.join(target_dir, 'assessment_scope.json')
        
        try:
            import json
            with open(scope_file, 'w') as f:
                json.dump(scope, f, indent=2)
            self.logger.success(f"Assessment scope saved: {scope_file}")
        except Exception as e:
            self.logger.error(f"Failed to save scope file: {e}")
            
        return True
        
    def execute(self):
        """Execute the preparation stage"""
        self.logger.info("═══ STAGE 1: PREPARATION ═══")
        
        try:
            # Step 1: Validate target
            if not self.validate_target():
                self.results['status'] = 'Target validation failed'
                return self.results
                
            # Step 2: Check environment
            self.check_environment()
            
            # Step 3: Setup workspace
            self.setup_workspace()
            
            # Step 4: Generate scope
            self.generate_scope_definition()
            
            # Check if preparation was successful
            target_valid = self.results['target_info'].get('type') is not None
            workspace_setup = any(
                dir_info.get('created', False) 
                for dir_info in self.results['setup_status'].get('directories', {}).values()
            )
            
            if target_valid and workspace_setup:
                self.results['success'] = True
                self.results['status'] = 'Preparation completed successfully'
                self.logger.success("Preparation stage completed successfully")
            else:
                self.results['status'] = 'Preparation completed with issues'
                self.logger.warning("Preparation stage completed with issues")
                
        except Exception as e:
            self.results['status'] = f'Preparation failed: {str(e)}'
            self.logger.error(f"Preparation stage failed: {e}")
            
        return self.results