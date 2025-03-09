import json
from llm import LLM
from pathlib import Path

class Reporter:
    """
    Security vulnerability reporter that analyzes findings and generates reports.
    
    Analyzes conversation history between security testing agent and target system
    to validate discovered vulnerabilities and generate detailed reports.
    """

    def __init__(self, starting_url, model_provider: str = "openai", model_name: str = None, debug: bool = False):
        """
        Initialize the reporter.

        Args:
            starting_url: Base URL that was tested
            model_provider: Provider to use ("openai" or "anthropic")
            model_name: Specific model to use (defaults to provider's recommended model)
            debug: Whether to enable debug output
        """
        self.debug = debug
        self.llm = LLM(model_provider=model_provider, model_name=model_name, debug=debug)
        self.reports = []
        self.starting_url = starting_url
        self.filename = str(self.starting_url).replace("https://", "").replace("http://", "").replace("/", "_")

    def report(self, history):
        """
        Analyze conversation history to validate if a real vulnerability was found.

        Uses strict criteria to evaluate if the conversation demonstrates a proven,
        exploitable vulnerability versus theoretical or low-severity issues.

        Args:
            history: List of conversation messages between agent and system

        Returns:
            Tuple of (bool, str) indicating if exploit was successful and detailed report
        """
        system_prompt = f"""
        You are a highly critical security vulnerability judge. Your job is to analyze a conversation between a security testing agent and determine if a REAL, WORKING exploit was actually discovered and proven.

        You must be extremely strict in your assessment. For a vulnerability to be considered valid, the conversation MUST show:
        1. A clear attack vector that was successfully exploited
        2. Concrete proof that the exploit worked (e.g. actual sensitive data accessed, actual code execution achieved)
        3. Specific technical details about how the exploit was performed
        4. The exact payload/steps that made it work

        You must REJECT findings that:
        - Are theoretical or potential vulnerabilities without proof
        - Only show error messages or unexpected behavior
        - Lack a working proof-of-concept exploit
        - Are low severity issues like mixed content, missing headers etc.
        - Make assumptions about what "could" be possible
        - Don't have explicit evidence of successful exploitation

        If and ONLY if you see clear evidence of a working exploit, create a brief report with:
        - Description of the proven vulnerability
        - The exact endpoint/component affected
        - The specific payload/steps that worked
        - Evidence showing successful exploitation
        
        For instance, if we have found a CSRF issue, is the endpoint actually an authentication endpoint? Is it sensitive? Similarly, if we have found an XSS issue, can the user really control that input? If there is a js engine inside the page and we can get an alert, that's not an issue at all. Vulnerabilities are rare, so you need to be extremely strict in your examination.

        A good criteria you can use is that if we submit it to hackerone, do we get a bounty of more than $1000? If so, it's probably a valid issue. But you rarely get that, right?!

        Remember: Your job is to eliminate false positives. Be extremely skeptical and demanding of proof.
        """

        system_prompt = [{"role": "system", "content": system_prompt}]
        history.append({"role": "user", "content": "Please analyze our conversation history and determine if any vulnerabilities were definitively proven with working exploits, or if the agent was just working lazily and stopped prematurely."})
        report = self.llm.reason(system_prompt + history)

        successful_exploit = self.parse_report(report)

        # Save reports as they are generated
        if successful_exploit:
            self.reports.append(report)
            self.save_reports()
        
        return successful_exploit, report

    def parse_report(self, report):
        """
        Parse a vulnerability report to determine if exploit was successful.

        Args:
            report: String containing the vulnerability report

        Returns:
            bool indicating if report demonstrates successful exploit
        """
        system_prompt = f"""
        You are a report parser whose task is to look at a report and its evaluation and return a boolean value indicating whether the report resulted in a successful exploit or not.

        Only return 1 word, either "yes" if the report resulted in a successful exploit or "no" if it did not.
        """

        system_prompt = [{"role": "system", "content": system_prompt}]
        response = self.llm.reason(system_prompt + [{"role": "user", "content": report}])
        response = str(response)
        return "yes" in response

    def save_reports(self):
        """Save all vulnerability reports to a text file."""
        report_path = Path("security_results") / f"{self.filename}.txt"
        with open(report_path, "w") as f:
            f.write("\n\n-------\n\n".join(self.reports))

    def generate_summary_report(self):
        """
        Generate a comprehensive markdown summary of all findings.
        
        Reads all previously saved reports and creates a well-formatted markdown
        document summarizing the vulnerabilities found, their severity, and
        technical details.
        """
        # Load all reports from file
        try:
            report_path = Path("security_results") / f"{self.filename}.txt"
            with open(report_path, "r") as f:
                report_content = f.read()
                
            # Check if there are actual reports to summarize
            if report_content.strip():
                system_prompt = f"""
                You are a security report summarizer. Your task is to analyze the security findings and create a comprehensive markdown summary report.

                For each vulnerability found:
                1. Provide a clear description of the vulnerability and its severity
                2. Detail the affected endpoint/component
                3. Include the exact payload/steps that were used to exploit it
                4. Document the proof/evidence that confirmed successful exploitation
                5. Explain potential impact and recommendations

                Format the output as a proper markdown document with:
                - Executive summary at the top
                - Table of contents
                - Detailed findings in separate sections
                - Technical details in code blocks
                - Clear headings and structure
                
                Focus on proven vulnerabilities with concrete evidence. Exclude theoretical or unproven issues.
                """

                system_prompt = [{"role": "system", "content": system_prompt}]
                summary = self.llm.reason(system_prompt + [{"role": "user", "content": report_content}])
            else:
                # No vulnerabilities were found, create a clean "no findings" report
                summary = self._generate_no_findings_report()
        except FileNotFoundError:
            # No report file exists, create a clean "no findings" report
            summary = self._generate_no_findings_report()
            
        # Save markdown summary report
        with open(f"security_results/{self.filename}_summary.md", "w") as f:
            f.write(summary)
            
    def _generate_no_findings_report(self):
        """Generate a standardized report for when no vulnerabilities were found."""
        return f"""# Security Assessment Summary: {self.starting_url}

## Executive Summary

A comprehensive security assessment was conducted on **{self.starting_url}** using automated scanning techniques and manual testing. No exploitable vulnerabilities were identified during this assessment.

## Assessment Details

- **Target:** {self.starting_url}
- **Assessment Date:** Auto-generated report
- **Assessment Type:** Web application security testing
- **Testing Methodology:** Combination of automated scanning and manual testing

## Findings Summary

No security vulnerabilities were identified during this assessment. This indicates that the application has successfully implemented security controls to protect against common web application vulnerabilities.

## Recommendations

While no vulnerabilities were found during this assessment, security is an ongoing process. We recommend:

1. **Regular Security Testing:** Continue to perform regular security assessments
2. **Security Monitoring:** Implement or maintain security monitoring systems
3. **Keep Dependencies Updated:** Regularly update all software dependencies
4. **Security Training:** Ensure development team stays current on security best practices

## Conclusion

Based on the assessment performed, no exploitable security vulnerabilities were identified in the target application. However, this does not guarantee that the application is completely secure, as new vulnerabilities and attack techniques emerge regularly.

---

*This report was automatically generated by Rogue Security Scanner*
"""
