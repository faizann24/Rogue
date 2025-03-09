import argparse
import os
from agent import Agent

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║                  Rogue - LLM Powered Security Scanner                ║
    ║                                                                      ║
    ║           Automated Penetration Testing with LLM Intelligence        ║
    ║                                                                      ║
    ║     [+] Intelligent vulnerability discovery                          ║
    ║     [+] Advanced payload generation                                  ║
    ║     [+] Context-aware testing                                        ║
    ║     [+] Automated exploit verification                               ║
    ║                                                                      ║
    ║                -- Happy hunting, use responsibly! --                 ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def parse_args():
    parser = argparse.ArgumentParser(
        description='AI-Powered Web Application Security Testing Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Basic scan of a single URL
    python run.py -u https://example.com -m o3-mini -o results

    # Advanced scan with subdomain enumeration and URL discovery
    python run.py -u https://example.com -e -s -m o3-preview -i 10
        '''
    )
    
    parser.add_argument('-u', '--url', 
                        required=True,
                        help='Target URL to test')

    parser.add_argument('-e', '--expand',
                        action='store_true',
                        default=False,
                        help='Expand testing to discovered URLs')
    
    parser.add_argument('-s', '--subdomains',
                        action='store_true',
                        default=False,
                        help='Perform subdomain enumeration')

    model_help_text = """LLM model to use (default: o3-mini)

OpenAI Models:
- o3-mini: Fast, cost-effective model for general tasks
- o1-preview: Advanced reasoning capabilities
- gpt-4o: Latest GPT-4 model with vision capabilities

Anthropic Claude Models:
- claude-3-7-sonnet-20250219: Latest flagship model with hybrid reasoning
- claude-3-7-sonnet-latest: Latest 3.7 Sonnet version (alias to 20250219)
- claude-3-5-sonnet-20241022: Balanced performance and capabilities
- claude-3-5-haiku-20241022: Fast, efficient model for simpler tasks

Note: As of March 2025, specific version IDs (e.g., 20250219) are recommended for production use."""

    parser.add_argument('-m', '--model',
                        choices=[
                            # OpenAI models
                            'o3-mini', 'o1-preview', 'gpt-4o',
                            
                            # Latest Claude models
                            'claude-3-7-sonnet-20250219',
                            'claude-3-7-sonnet-latest',
                            'claude-3-5-sonnet-20241022',
                            'claude-3-5-haiku-20241022'
                        ],
                        default='o3-mini',
                        help=model_help_text)
    
    parser.add_argument('-p', '--provider',
                        choices=['openai', 'anthropic', 'auto'],
                        default='auto',
                        help='LLM provider to use (default: auto - determines provider from model name)')
    
    parser.add_argument('-o', '--output',
                        default='security_results',
                        help='Output directory for results (default: security_results)')
    
    parser.add_argument('-i', '--max-iterations',
                        type=int,
                        default=10,
                        help='Maximum iterations per plan of attack (default: 10)')
    
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        default=False,
                        help='Enable debug output for troubleshooting')

    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)
    
    return args

if __name__ == "__main__":
    print_banner()
    args = parse_args()
    # Determine provider if set to auto
    provider = args.provider
    if provider == 'auto':
        if args.model.startswith('claude'):
            provider = 'anthropic'
        else:
            provider = 'openai'
    
    print("\n[*] Starting security scan...")
    print(f"[*] Target URL: {args.url}")
    print(f"[*] Using model: {args.model} (Provider: {provider})")
    print(f"[*] Results will be saved to: {args.output}\n")
    
    agent = Agent(
        starting_url=args.url,
        expand_scope=args.expand,
        enumerate_subdomains=args.subdomains,
        model=args.model,
        provider=provider,
        output_dir=args.output,
        max_iterations=args.max_iterations,
        debug=args.debug
    )
    agent.run()
