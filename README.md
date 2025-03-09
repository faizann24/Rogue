<p align="center">
  <img src="logo/logo.png" alt="Rogue Logo" width="270"/>
</p>

# Rogue 🎯
> An intelligent web vulnerability scanner agent powered by Large Language Models

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Rogue is an advanced AI security testing agent that leverages Large Language Models to intelligently discover and validate web application vulnerabilities. Unlike traditional scanners that follow predefined patterns, Rogue thinks like a human penetration tester - analyzing application behavior, generating sophisticated test cases, and validating findings through autonomous decision making.

Note: This is a very early release with many planned improvements and features still in development. Open source contributions are most welcome.

<p align="center">
  <img src="logo/demo.gif" alt="Demo GIF"/>
</p>

## 🌟 Key Features

- **Intelligent Vulnerability Discovery**: Uses LLMs (OpenAI and Anthropic Claude) to understand application context and identify potential security weaknesses
- **Advanced Payload Generation**: Creates sophisticated test payloads tailored to the target application
- **Context-Aware Testing**: Analyzes application behavior and responses to guide testing strategy
- **Automated Exploit Verification**: Validates findings to eliminate false positives
- **Comprehensive Reporting**: Generates detailed vulnerability reports with reproduction steps
- **Subdomain Enumeration**: Optional discovery of related subdomains
- **Traffic Monitoring**: Built-in proxy captures and analyzes all web traffic
- **Expandable Scope**: Option to recursively test discovered URLs

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API key (for using OpenAI models)
- Anthropic API key (optional, for using Claude models)
- Playwright

### Installation

```bash
# Clone the repository
git clone https://github.com/faizann24/rogue
cd rogue

# Install dependencies
pip install -r requirements.txt

# Set up your OpenAI API key
export OPENAI_API_KEY='your-openai-key-here'

# For Anthropic Claude models (optional)
export ANTHROPIC_API_KEY='your-anthropic-key-here'
```

### Basic Usage

```bash
# Basic scan of a single URL
python run.py -u https://example.com

# Advanced scan with subdomain enumeration and URL discovery (OpenAI)
python run.py -u https://example.com -e -s -m o3-mini -i 10

# Using Anthropic Claude models
python run.py -u https://example.com -p anthropic -m claude-3-7-sonnet-20250219

# Using Anthropic Claude with extended thinking capabilities
python run.py -u https://example.com -p anthropic -m claude-3-7-sonnet-latest -e -s

# Using faster Anthropic Claude model
python run.py -u https://example.com -p anthropic -m claude-3-5-haiku-20241022
```

## 🛠️ Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL to test (required) |
| `-e, --expand` | Expand testing to discovered URLs |
| `-s, --subdomains` | Perform subdomain enumeration |
| `-p, --provider` | LLM provider to use (openai or anthropic) |
| `-m, --model` | LLM model to use (OpenAI: o3-mini, o1-preview, gpt-4o; Anthropic: claude-3-7-sonnet-20250219, claude-3-7-sonnet-latest, claude-3-5-sonnet-20241022, claude-3-5-haiku-20241022) |
| `-o, --output` | Output directory for results |
| `-i, --max-iterations` | Maximum iterations per plan of attack |

## 🏗️ Architecture

Rogue is built with a modular architecture consisting of several key components:

- **Agent**: Orchestrates the scanning process and manages other components
- **Planner**: Generates intelligent testing strategies using LLMs with support for multiple providers (OpenAI and Anthropic)
- **Scanner**: Handles web page interaction and data collection
- **Proxy**: Monitors and captures network traffic
- **Reporter**: Analyzes findings and generates detailed reports
- **Tools**: Collection of testing and exploitation tools
- **LLM Providers**: Supports both OpenAI and Anthropic Claude models with provider-specific optimizations

## 📊 Example Report

Reports are generated in both text and markdown formats, containing:

- Executive summary
- Detailed findings with severity ratings
- Technical details and reproduction steps
- Evidence and impact analysis
- Remediation recommendations

## 🔒 Security Considerations

- Always obtain proper authorization before testing
- Use responsibly and ethically
- Follow security testing best practices
- Be mindful of potential impact on target systems

## 📋 TODOs

- [x] Add support for Anthropic Claude models
- [ ] Integrate vision API capabilities for visual analysis
- [ ] Run against HackerOne reports to find first LLM-powered vulnerability in the wild
- [ ] Implement more sophisticated planning algorithms
- [ ] Add better execution strategies and error handling
- [ ] Support for custom LLM model deployment
- [ ] Add collaborative testing capabilities
- [ ] Improve subdomain enumeration techniques
- [ ] Add API security testing capabilities
- [x] ~~Add basic documentation and examples~~


## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the GPL3 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for security professionals and researchers. Always obtain proper authorization before testing any systems you don't own. The authors are not responsible for any misuse or damage caused by this tool.

## 🙏 Acknowledgments

- OpenAI for their powerful language models
- Playwright for web automation capabilities
- The security research community for inspiration and guidance

## 📧 Contact

For questions, feedback, or issues, please:
- Open an issue in this repository
- Contact the maintainers at [faizann288@gmail.com]

---
Made with ❤️ by Faizan
