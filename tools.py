import sys
import re
from io import StringIO
from llm import LLM


class Tools:
    """
    Collection of tools for interacting with web pages and executing code.
    Provides methods for page manipulation, JavaScript execution, and Python code evaluation.
    """

    def __init__(self, model_provider: str = "openai", model_name: str = None, debug: bool = False):
        """
        Initialize Tools with LLM instance.
        
        Args:
            model_provider: Provider to use ("openai" or "anthropic")
            model_name: Specific model to use (defaults to provider's recommended model)
            debug: Whether to enable debug output
        """
        self.debug = debug
        self.llm = LLM(model_provider=model_provider, model_name=model_name, debug=debug)
        # Security testing state tracking
        self.security_actions_performed = 0
        self.min_actions_required = 3  # Minimum security actions required before completion
        self.first_navigation = False
        # Initialize the page object storage
        self.current_page = None
        
    def execute_js(self, page, js_code: str) -> str:
        """Execute JavaScript code on the page.
        
        Args:
            page: Playwright page object
            js_code: JavaScript code to execute
            
        Returns:
            Result of JavaScript evaluation
        """
        # Validate and fix common JavaScript issues
        js_code = self._validate_and_fix_js_code(js_code)
        
        try:
            # Count this as a security action (JS execution is often used for testing)
            self.security_actions_performed += 1
            return page.evaluate(js_code)
        except Exception as e:
            if "Illegal return statement" in str(e) and not js_code.strip().startswith("() =>"):
                # Try wrapping in an anonymous function
                wrapped_code = f"() => {{ {js_code} }}"
                if self.debug:
                    print(f"Retrying with wrapped JS code: {wrapped_code}")
                return page.evaluate(wrapped_code)
            raise
            
    def _validate_and_fix_js_code(self, js_code: str) -> str:
        """Validate and fix common JavaScript issues.
        
        Args:
            js_code: JavaScript code to validate and fix
            
        Returns:
            Fixed JavaScript code
        """
        import re
        
        # First, check for any nested tool calls and remove them
        # This prevents issues like execute_js(page, "execute_js(page, """)
        if re.search(r'(?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\(', js_code):
            # We found what appears to be a nested tool call, clean it up
            if self.debug:
                print(f"WARNING: Possible nested tool call detected in JS code: {js_code}")
            # Extract just the JavaScript part if possible, otherwise use a safe default
            js_code = "() => document.documentElement.innerHTML"
        
        # Ensure code doesn't contain unbalanced parentheses
        open_parens = js_code.count('(')
        close_parens = js_code.count(')')
        if open_parens != close_parens:
            if self.debug:
                print(f"WARNING: Unbalanced parentheses in JS code: {js_code}")
            # Simplify to a safe default if the JS is likely malformed
            js_code = "() => document.documentElement.innerHTML"
        
        # Fix standalone return statements
        if js_code.strip().startswith('return '):
            js_code = f"() => {{ {js_code} }}"
        
        # Ensure async/await is properly handled
        if 'await ' in js_code and not js_code.strip().startswith('async'):
            if js_code.strip().startswith('() =>'):
                js_code = js_code.replace('() =>', 'async () =>')
            elif not js_code.strip().startswith('async () =>'):
                js_code = f"async () => {{ {js_code} }}"
        
        # Fix direct document.querySelector usage to ensure it's wrapped properly
        if 'document.querySelector' in js_code and not '() =>' in js_code:
            js_code = f"() => {{ {js_code} }}"
        
        # Remove standalone console.log statements without return values
        if 'console.log' in js_code and not 'return' in js_code:
            js_code = js_code.replace('console.log(', 'return console.log(')
            
        return js_code

    def click(self, page, css_selector: str) -> str:
        """Click an element on the page.
        
        Args:
            page: Playwright page object
            css_selector: CSS selector for element to click
            
        Returns:
            Page HTML after click
        """
        page.click(css_selector, timeout=5000)
        # Count this as a security action (interaction with the page)
        self.security_actions_performed += 1
        return page.inner_html("html")

    def fill(self, page, css_selector: str, value: str) -> str:
        """Fill a form field.
        
        Args:
            page: Playwright page object
            css_selector: CSS selector for input field
            value: Value to fill
            
        Returns:
            Page HTML after filling
        """
        page.fill(css_selector, value, timeout=5000)
        # Count this as a security action (form interaction is common for testing)
        self.security_actions_performed += 1
        return page.inner_html("html")

    def submit(self, page, css_selector: str) -> str:
        """Submit a form by clicking an element.
        
        Args:
            page: Playwright page object
            css_selector: CSS selector for submit element
            
        Returns:
            Page HTML after submission
        """
        page.locator(css_selector).click()
        # Count this as a security action (form submission is critical for testing)
        self.security_actions_performed += 1
        return page.inner_html("html")

    def presskey(self, page, key: str) -> str:
        """Press a keyboard key.
        
        Args:
            page: Playwright page object
            key: Key to press
            
        Returns:
            Page HTML after key press
        """
        page.keyboard.press(key)
        # Count this as a security action
        self.security_actions_performed += 1
        return page.inner_html("html")

    def goto(self, page, url: str) -> str:
        """Navigate to a URL.
        
        Args:
            page: Playwright page object
            url: URL to navigate to
            
        Returns:
            Page HTML after navigation
        """
        # Define an expanded URL mapping for common keywords
        URL_MAPPING = {
            "documentation": "/docs/",
            "docs": "/docs/",
            "doc": "/docs/",
            "api": "/api/",
            "swagger": "/swagger/",
            "api-docs": "/api-docs/",
            "home": "/",
            "login": "/login/",
            "admin": "/admin/"
        }
        
        # Clean up URL - remove any trailing natural language
        if url and ' ' in url:
            # Extract just the URL part before any natural language description
            import re
            url_match = re.match(r'([^"\']*?(?:\.html|\.php|\.aspx|\.js|\.css|\.json|\/)?)(?:\s|$)', url)
            if url_match:
                url = url_match.group(1)
            else:
                # If no clear endpoint, take everything before the first space
                url = url.split(' ')[0]
                
            if self.debug:
                print(f"Cleaned URL from natural language: '{url}'")
        
        # Handle keyword to URL mapping with proper sanitization
        if url and not url.startswith(('http://', 'https://', '/')):
            # Check for exact match in URL_MAPPING
            url_lower = url.lower().strip()
            if url_lower in URL_MAPPING:
                url = URL_MAPPING[url_lower]
            else:
                # For any other string that's not in our mapping, add leading slash
                url = '/' + url.lstrip('/')
            
            # Log when conversions happen for monitoring
            if self.debug:
                print(f"URL mapping converted '{url_lower}' to path '{url}'")
        
        # Sanitize paths to prevent traversal attacks
        url = url.replace('../', '')
        
        # Fix relative URLs
        if url.startswith('/'):
            if hasattr(self, 'current_url') and self.current_url:
                # Extract base URL from current URL
                import re
                base_url = re.match(r'(https?://[^/]+)', self.current_url)
                if base_url:
                    url = base_url.group(1) + url
                else:
                    # Fallback - prepend the current domain if we can extract it
                    from urllib.parse import urlparse
                    parsed = urlparse(self.current_url)
                    if parsed.netloc:
                        url = f"{parsed.scheme}://{parsed.netloc}{url}"
            
        # Store the current URL for future reference
        self.current_url = url
        
        # Only count as a security action if this isn't the initial navigation
        # or if it's navigating to a non-root path that might be more interesting for testing
        if self.first_navigation or '/' in url[8:]:
            self.security_actions_performed += 1
        else:
            # Mark that we've done the first navigation
            self.first_navigation = True
            
        try:
            page.goto(url)
            return page.inner_html("html")
        except Exception as e:
            # If navigation fails with the current URL, try adding /docs/ as fallback
            if "/docs/" not in url and "documentation" in url.lower():
                try:
                    # Extract base domain and add /docs/
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    fallback_url = f"{parsed.scheme}://{parsed.netloc}/docs/"
                    print(f"Primary navigation failed. Trying fallback to {fallback_url}")
                    page.goto(fallback_url)
                    return page.inner_html("html")
                except:
                    # If fallback fails, re-raise the original error
                    raise e
            else:
                # Re-raise the original error
                raise

    def refresh(self, page) -> str:
        """Refresh the current page.
        
        Args:
            page: Playwright page object
            
        Returns:
            Page HTML after refresh
        """
        page.reload()
        # Count this as a security action
        self.security_actions_performed += 1
        return page.inner_html("html")

    def python_interpreter(self, code: str) -> str:
        """Execute Python code and capture output.
        
        Args:
            code: Python code to execute
            
        Returns:
            Output from code execution
        """
        output_buffer = StringIO()
        old_stdout = sys.stdout
        sys.stdout = output_buffer
        
        try:
            exec(code)
            output = output_buffer.getvalue()
            # Count this as a security action (code execution is important for testing)
            self.security_actions_performed += 1
            return output
        finally:
            sys.stdout = old_stdout
            output_buffer.close()

    def get_user_input(self, prompt: str) -> str:
        """Get input from user.
        
        Args:
            prompt: Prompt to display to user
            
        Returns:
            Confirmation message
        """
        input(prompt)
        return "Input done!"

    def execute_tool(self, page, tool_use: str):
        """Execute a tool command.
        
        Args:
            page: Playwright page object
            tool_use: Tool command to execute
            
        Returns:
            Result of tool execution or error message
        """
        try:
            # Store the page object for this execution
            self.current_page = page
            
            # Parse the command instead of using direct eval
            command_match = re.match(r'(\w+)\s*\((.*)\)', tool_use)
            if not command_match:
                return f"Error executing tool: Invalid command format: {tool_use}"
                
            func_name = command_match.group(1)
            args_str = command_match.group(2)
            
            # Validate that the function exists
            if not hasattr(self, func_name):
                return f"Error executing tool: Unknown function: {func_name}"
            
            # Get the function object
            func = getattr(self, func_name)
            
            # Special case for functions that need page object
            page_required = func_name in ['goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey']
            
            # Parse arguments safely
            if not args_str:
                # No arguments
                return func()
            elif page_required and not args_str.startswith('page'):
                # Add page as first argument if needed
                modified_args_str = f"page, {args_str}"
                # Execute with safe argument parsing
                return self._execute_with_args(func, modified_args_str)
            else:
                # Execute with existing arguments
                return self._execute_with_args(func, args_str)
                
        except Exception as e:
            return f"Error executing tool: {str(e)}"
            
    def _execute_with_args(self, func, args_str):
        """Execute a function with parsed arguments.
        
        Args:
            func: Function to execute
            args_str: String containing argument values
            
        Returns:
            Result of function execution
        """
        import re
        
        # Parse the arguments string safely
        args = []
        kwargs = {}
        
        # Handle empty args
        if not args_str.strip():
            return func()
            
        # Special handling for quotes in arguments to prevent syntax errors
        # First, handle the page argument if it exists
        if args_str.startswith('page'):
            # Use the stored current_page instead of assuming global 'page' variable
            if self.current_page is None:
                raise ValueError("Page object not available. Make sure page is passed to execute_tool first.")
            args.append(self.current_page)
            # Remove the page argument and any following comma
            args_str = re.sub(r'^page\s*,\s*', '', args_str)
        
        # Special handling for known security tools with XSS payloads
        # If this is a fill command with a potential XSS payload, use a more robust parsing approach
        is_fill_with_xss = func.__name__ == 'fill' and ('<script>' in args_str or 'alert(' in args_str)
        
        if is_fill_with_xss and args_str.count(',') >= 1:
            # For fill commands with XSS payloads, use a more specialized parsing approach
            try:
                # First, extract the selector (everything up to the first comma)
                first_comma_idx = self._find_safe_comma_position(args_str)
                if first_comma_idx == -1:
                    # Fallback if we can't find a safe comma
                    raise ValueError("Cannot parse arguments for fill command")
                    
                selector = args_str[:first_comma_idx].strip()
                value = args_str[first_comma_idx + 1:].strip()
                
                # Parse the selector and value
                args.append(self._parse_arg_value(selector))
                args.append(self._parse_arg_value(value))
                
                if self.debug:
                    print(f"XSS payload detected. Parsed args: selector='{args[0]}', value='{args[1]}'")
                
                # Execute with the parsed arguments
                return func(*args)
            except Exception as e:
                if self.debug:
                    print(f"Error parsing XSS payload: {str(e)}. Falling back to standard parser.")
                # If specialized parsing fails, fall back to the standard approach
        
        # Standard argument parsing for other cases
        # Split by commas, but respect quotes
        in_quotes = False
        quote_char = None
        current_arg = ""
        escaped = False
        bracket_depth = 0  # Track depth of angle brackets (for HTML/XML tags)
        
        for char in args_str:
            if escaped:
                current_arg += char
                escaped = False
                continue
                
            if char == '\\':
                escaped = True
                current_arg += char
                continue
            
            # Track angle brackets for HTML/XML content
            if char == '<':
                bracket_depth += 1
            elif char == '>':
                bracket_depth = max(0, bracket_depth - 1)  # Prevent negative depth
                
            if char in ['"', "'"]:
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
                current_arg += char
            elif char == ',' and not in_quotes and bracket_depth == 0:
                # End of argument - only split on commas that are not inside quotes or HTML tags
                args.append(self._parse_arg_value(current_arg.strip()))
                current_arg = ""
            else:
                current_arg += char
        
        # Add the last argument if there is one
        if current_arg.strip():
            args.append(self._parse_arg_value(current_arg.strip()))
        
        # Execute the function with the parsed arguments
        return func(*args)
    
    def _find_safe_comma_position(self, args_str):
        """Find a safe position for the first comma that's not inside quotes or HTML tags.
        
        Args:
            args_str: String containing argument values
            
        Returns:
            Position of the first safe comma, or -1 if not found
        """
        in_quotes = False
        quote_char = None
        bracket_depth = 0
        escaped = False
        
        for i, char in enumerate(args_str):
            if escaped:
                escaped = False
                continue
                
            if char == '\\':
                escaped = True
                continue
                
            # Track quotes
            if char in ['"', "'"]:
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
            
            # Track angle brackets
            elif char == '<':
                bracket_depth += 1
            elif char == '>':
                bracket_depth = max(0, bracket_depth - 1)
                
            # Check for safe comma
            elif char == ',' and not in_quotes and bracket_depth == 0:
                return i
                
        return -1
        
    def _parse_arg_value(self, arg_str):
        """Parse an argument string to its appropriate Python value.
        
        Args:
            arg_str: String representation of the argument
            
        Returns:
            Parsed argument value
        """
        # Safety check for empty strings
        if not arg_str or arg_str.isspace():
            return ""
            
        # Strip quotes if the argument is a quoted string
        if (arg_str.startswith('"') and arg_str.endswith('"')) or \
           (arg_str.startswith("'") and arg_str.endswith("'")):
            # Remove the quotes and handle escaped quotes inside
            inner_str = arg_str[1:-1]
            # Return the actual string without modifications (to preserve HTML/JavaScript content)
            return inner_str
            
        # Handle numeric values
        try:
            if '.' in arg_str:
                return float(arg_str)
            else:
                return int(arg_str)
        except ValueError:
            # Not a number, return as is
            return arg_str

    def auth_needed(self) -> str:
        """Prompt for user authentication.
        
        Returns:
            Confirmation message
        """
        input("Authentication needed. Please login and press enter to continue.")
        # Count this as a security action
        self.security_actions_performed += 1
        return "Authentication done!"

    def complete(self) -> str:
        """Mark current task as complete with validation.
        
        Checks if sufficient security testing has been performed before allowing completion.
        
        Returns:
            Completion message or rejection message
        """
        if self.security_actions_performed < self.min_actions_required:
            # Not enough security testing was performed
            return "Completion rejected: Insufficient security testing performed. Please continue testing with more actions before marking complete."
        # Reset action counter for next test plan
        self.security_actions_performed = 0
        return "Completed"

    def _validate_and_fix_selectors(self, tool_use: str) -> str:
        """Validate and fix selectors in a tool use string.
        
        Args:
            tool_use: Tool use string that may contain selectors
            
        Returns:
            Fixed tool use string with validated selectors
        """
        # Import re at the top level instead
        import re
        
        # Check for common selector patterns in tool functions
        selector_patterns = [
            (r'click\s*\(\s*page\s*,\s*["\']([^"\']*)', r'click(page, "{}")'),
            (r'fill\s*\(\s*page\s*,\s*["\']([^"\']*)["\']', r'fill(page, "{}")'),
            (r'submit\s*\(\s*page\s*,\s*["\']([^"\']*)', r'submit(page, "{}")'),
        ]
        
        # Fix each type of selector pattern
        for pattern, template in selector_patterns:
            matches = re.finditer(pattern, tool_use)
            for match in matches:
                # Extract the selector part
                selector = match.group(1)
                # Sanitize the selector
                fixed_selector = self._sanitize_selector(selector)
                # Replace in the original string if changed
                if fixed_selector != selector:
                    # Create the replacement part 
                    original = match.group(0)
                    replacement = template.format(fixed_selector)
                    # Replace just this instance
                    tool_use = tool_use.replace(original, replacement, 1)
        
        return tool_use
    
    def _sanitize_selector(self, selector: str) -> str:
        """Sanitize and fix a CSS selector.
        
        Args:
            selector: CSS selector to sanitize
            
        Returns:
            Sanitized CSS selector
        """
        import re
        
        # Ensure selector doesn't contain unbalanced quotes
        if selector.count('"') % 2 != 0:
            # If odd number of double quotes, remove them all
            selector = selector.replace('"', '')
        
        if selector.count("'") % 2 != 0:
            # If odd number of single quotes, remove them all
            selector = selector.replace("'", '')
        
        # Fix common selector issues
        # Fix a[href= -> a[href=""]
        selector = re.sub(r'(\w+)\[(\w+)=([^\]]*)?\]', r'\1[\2="\3"]', selector)
        
        # Ensure attribute selectors have quotes
        # a[href=docs/] -> a[href="docs/"]
        selector = re.sub(r'(\w+)\[(\w+)=([^"\'\]]+)\]', r'\1[\2="\3"]', selector)
        
        # Handle common incomplete selectors
        # a[href= -> a[href=""]
        if selector.endswith('='):
            selector = selector + '""'
        
        # a[href -> a[href=""]
        if re.search(r'\[\w+$', selector):
            selector = selector + '=""]'
        
        return selector

    def extract_tool_use(self, action: str) -> str:
        """Extract tool command from action description.
        
        Args:
            action: Description of action to take
            
        Returns:
            Tool command to execute
        """
        import re
        
        # Safety check for empty input
        if not action or action.isspace():
            if self.debug:
                print("Empty action text, defaulting to docs navigation")
            return 'goto(page, "/docs/")'
        
        # Clean up the input - remove any "REFORMATTED:" text or similar prefixes
        action = re.sub(r'REFORMATTED:\s*', '', action)
        
        # First try to extract using pattern matching for ACTION section
        action_pattern = r'\*\s*ACTION\s*\n(.*?)(?:\n|$)'
        action_match = re.search(action_pattern, action, re.IGNORECASE)
        
        if action_match:
            # Extract the raw command
            raw_tool_use = action_match.group(1).strip()
            
            # Fix any unterminated string literals first at this stage
            raw_tool_use = self._fix_unterminated_strings(raw_tool_use)
            
            # Extract just the command part, excluding any explanatory text that follows
            # This pattern looks for a complete function call with balanced parentheses
            complete_command_pattern = r'((?:goto|click|fill|submit|execute_js|refresh|presskey|auth_needed|get_user_input|python_interpreter|complete)\s*\([^)]*\))'
            complete_command_match = re.search(complete_command_pattern, raw_tool_use)
            
            if complete_command_match:
                # We found a properly formatted command with balanced parentheses
                tool_use = complete_command_match.group(1)
            else:
                # No complete command found, look for a partial command pattern
                partial_command_pattern = r'((?:goto|click|fill|submit|execute_js|refresh|presskey|auth_needed|get_user_input|python_interpreter|complete)\s*\([^)]*)'
                partial_command_match = re.search(partial_command_pattern, raw_tool_use)
                
                if partial_command_match:
                    # Get the partial command
                    tool_use = partial_command_match.group(1)
                    
                    # Find if there's any trailing text after a quoted string that should be removed
                    # This handles cases like: goto(page, "url") to understand what endpoints are available
                    last_quote = max(tool_use.rfind('"'), tool_use.rfind("'"))
                    if last_quote > 0:
                        space_after_quote = tool_use.find(' ', last_quote + 1)
                        if space_after_quote > 0:
                            tool_use = tool_use[:space_after_quote]
                    
                    # Make sure command ends with closing parenthesis
                    if not tool_use.endswith(')'):
                        tool_use += ')'
                else:
                    # No well-formed command found, use the entire line
                    tool_use = raw_tool_use
                    if self.debug:
                        print(f"Using full ACTION text as no clean command found: '{tool_use}'")
                
            # Fix common issues before full processing
            tool_use = self._pre_process_tool_use(tool_use)
            
            # Validate and fix the extracted tool use
            return self._fix_tool_use(tool_use)
        
        # If no explicit ACTION section, try to detect command-like statements
        # Look for common patterns in natural language descriptions
        url_navigate_pattern = r'(?:navigate|go|visit|browse)\s+(?:to|the)?\s+(?:URL|page|website|site|link|documentation)?\s*(?:at|:)?\s*[\'"]?(https?://[^\s\'"]+)[\'"]?'
        url_match = re.search(url_navigate_pattern, action, re.IGNORECASE)
        if url_match:
            url = url_match.group(1)
            return f'goto(page, "{url}")'
            
        # Look for "curl" commands
        curl_pattern = r'curl\s+(https?://[^\s]+)'
        curl_match = re.search(curl_pattern, action, re.IGNORECASE)
        if curl_match:
            url = curl_match.group(1)
            return f'goto(page, "{url}")'
            
        # Look for documentation references specifically
        docs_pattern = r'(?:docs|documentation|api\s*docs)'
        if re.search(docs_pattern, action, re.IGNORECASE):
            if hasattr(self, 'current_url') and self.current_url:
                # Try to construct a docs URL from the current URL
                import re
                base_url = re.match(r'(https?://[^/]+)', self.current_url)
                if base_url:
                    return f'goto(page, "{base_url.group(1)}/docs/")'
            
            # Default to a generic /docs/ path if we can't determine a base URL
            return 'goto(page, "/docs/")'
        
        # Try direct extraction of tool commands with proper page parameter
        command_with_page_pattern = r'((?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\(\s*page\s*,\s*[^)]*\))'
        command_with_page_match = re.search(command_with_page_pattern, action)
        if command_with_page_match:
            return command_with_page_match.group(1)
        
        # Try direct extraction of tool commands that might be missing page parameter
        command_pattern = r'((?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\([^)]*\))'
        command_match = re.search(command_pattern, action)
        if command_match:
            # Fix and return the extracted command
            return self._fix_tool_use(command_match.group(1))
        
        # If no direct command found, try with LLM-based extraction as last resort
        prompt = f"""
            Convert the following text into a SINGLE valid tool call for a security testing agent.
            Choose from these tools only:
            
            goto(page, "URL") - Navigate to a URL
            click(page, "selector") - Click an element
            fill(page, "selector", "value") - Fill a form field
            submit(page, "selector") - Submit a form
            execute_js(page, "js_code") - Run JavaScript code
            auth_needed() - Signal authentication is needed
            refresh(page) - Refresh the page
            complete() - Mark test as complete
            
            IMPORTANT: ALL tools that interact with the page MUST have 'page' as the FIRST parameter.
            
            Text to convert:
            {action}
            
            ONLY RETURN the exact code for the function call with no explanations, quotes, markdown syntax, or other text.
            Examples:
            - "navigate to the documentation" → goto(page, "/docs/")
            - "check authentication" → auth_needed()
            - "submit the login form" → submit(page, "#login-form")
        """
        response = self.llm.output(prompt, temperature=0)
        
        # Clean up LLM response
        response = response.strip()
        response = re.sub(r'^```.*?\n', '', response)  # Remove opening code fence if present
        response = re.sub(r'\n```$', '', response)     # Remove closing code fence if present
        response = re.sub(r'^`|`$', '', response)      # Remove single backticks
        response = re.sub(r'^\s*-\s+', '', response)   # Remove bullet points if present
        
        # Process and fix the LLM-generated command
        return self._fix_tool_use(response)
        
    def _fix_unterminated_strings(self, text: str) -> str:
        """Fix unterminated string literals in text.
        
        Args:
            text: Text that might contain unterminated string literals
            
        Returns:
            Fixed text with properly terminated string literals
        """
        import re
        
        # If empty or None, return safely
        if not text:
            return ""
            
        # Count single and double quotes to check for balance
        single_quotes = text.count("'")
        double_quotes = text.count('"')
        
        # Fix functions with unterminated string literals
        # Match common patterns like goto(page, "url but with missing closing quote
        patterns = [
            # goto with unterminated string: goto(page, "url
            (r'(goto\s*\(\s*page\s*,\s*["\'])([^"\']*?)(?:\s*$)', r'\1\2\1)'),
            # execute_js with unterminated string: execute_js(page, "code
            (r'(execute_js\s*\(\s*page\s*,\s*["\'])([^"\']*?)(?:\s*$)', r'\1\2\1)'),
            # click with unterminated string: click(page, "selector
            (r'(click\s*\(\s*page\s*,\s*["\'])([^"\']*?)(?:\s*$)', r'\1\2\1)'),
            # fill with unterminated string: fill(page, "selector", "value
            (r'(fill\s*\(\s*page\s*,\s*["\'])([^"\']*?)(?:\s*,\s*["\'])([^"\']*?)(?:\s*$)', r'\1\2\1, \1\3\1)'),
        ]
        
        # Apply fixes for each pattern
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text)
            
        # If quotes are imbalanced, fix general cases
        if single_quotes % 2 != 0:
            # Find the last single quote and any text after it
            last_quote_pos = text.rfind("'")
            if last_quote_pos >= 0:
                # Add a closing quote right after the last one found
                text = text[:last_quote_pos+1] + "'" + text[last_quote_pos+1:]
                
        if double_quotes % 2 != 0:
            # Find the last double quote and any text after it
            last_quote_pos = text.rfind('"')
            if last_quote_pos >= 0:
                # Add a closing quote right after the last one found
                text = text[:last_quote_pos+1] + '"' + text[last_quote_pos+1:]
                
        # Ensure all function calls have closing parentheses
        if ('(' in text) and (')' not in text):
            text += ')'
            
        if self.debug:
            print(f"Fixed unterminated strings in: '{text}'")
            
        return text
        
    def _pre_process_tool_use(self, tool_use: str) -> str:
        """
        Pre-process the tool use string to fix common text issues before full processing.
        
        Args:
            tool_use: Raw tool use string
            
        Returns:
            Pre-processed tool use string
        """
        import re
        
        # Safety check
        if not tool_use or tool_use.isspace():
            return 'goto(page, "/docs/")'
        
        # Remove any stray text that might cause parsing issues
        tool_use = re.sub(r'```.*?```', '', tool_use, flags=re.DOTALL)
        tool_use = re.sub(r'Let\'s|I\'ll|We should', '', tool_use)
        
        # Fix common natural language patterns to commands
        tool_use = re.sub(r'navigate\s+to\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        tool_use = re.sub(r'go\s+to\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        tool_use = re.sub(r'visit\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        
        # Convert curl commands to goto
        tool_use = re.sub(r'curl\s+(https?://[^\s"\']+)', r'goto(page, "\1")', tool_use)
        
        # Fix documentation references
        if 'documentation' in tool_use.lower() and not ('goto' in tool_use or 'click' in tool_use):
            return 'goto(page, "/docs/")'
        
        # Check for any trailing text after parentheses (like explanatory comments)
        # e.g., "goto(page, 'url') to understand the API"
        if ')' in tool_use:
            closing_paren_pos = tool_use.find(')')
            if closing_paren_pos < len(tool_use) - 1:
                # Keep only up to the closing parenthesis
                tool_use = tool_use[:closing_paren_pos+1]
        
        # Fix any unterminated strings that might be present
        tool_use = self._fix_unterminated_strings(tool_use)
            
        return tool_use
    
    def _fix_tool_use(self, tool_use: str) -> str:
        """Fix common issues with tool use extraction and add a layer of validation.
        
        Args:
            tool_use: Extracted tool use
            
        Returns:
            Fixed tool use
        """
        import re
        
        # Handle completely invalid inputs with strong defaults
        if not tool_use or tool_use.isspace():
            return 'goto(page, "/docs/")'
            
        # Remove problematic characters that might cause syntax errors
        tool_use = tool_use.replace('\\"', '"').replace("\\'", "'")
        
        # Check for nested tool calls (like execute_js inside execute_js) and fix
        nested_tool_pattern = r'(goto|click|fill|submit|execute_js|refresh|presskey)\s*\(\s*page\s*,\s*.*?(goto|click|fill|submit|execute_js|refresh|presskey)'
        if re.search(nested_tool_pattern, tool_use):
            # Extract just the outer function
            outer_func_match = re.match(r'(\w+)\s*\(', tool_use)
            if outer_func_match:
                func_name = outer_func_match.group(1)
                if func_name == 'execute_js':
                    # For execute_js, use a simple document.body command
                    return 'execute_js(page, "() => document.documentElement.innerHTML")'
                elif func_name == 'goto':
                    # For goto, navigate to docs
                    return 'goto(page, "/docs/")'
            # Default fallback
            return 'goto(page, "/docs/")'
        
        # Fix any unterminated strings in the command
        tool_use = self._fix_unterminated_strings(tool_use)
        
        # Validate and fix selectors in the tool use string
        tool_use = self._validate_and_fix_selectors(tool_use)
        
        # If the input looks like natural language and not a command
        if not any(cmd in tool_use for cmd in ['goto(', 'click(', 'fill(', 'execute_js(', 'submit(', 'auth_needed(', 'refresh(', 'complete(']):
            # Try to extract a URL and create a goto command
            url_match = re.search(r'(https?://[^\s"\']+)', tool_use)
            if url_match:
                return f'goto(page, "{url_match.group(1)}")'
                
            # Check for potential documentation references
            if any(term in tool_use.lower() for term in ['doc', 'documentation', 'api', 'swagger']):
                return 'goto(page, "/docs/")'
                
            # Check for potential login references
            if any(term in tool_use.lower() for term in ['login', 'sign in', 'authenticate']):
                return 'goto(page, "/login/")'
                
            # Default to reasonable action for natural language input
            if "click" in tool_use.lower():
                # Look for potential element references in the text
                element_match = re.search(r'(?:the\s+)?([a-zA-Z0-9_-]+\s+(?:button|link|form|input|element))', tool_use.lower())
                if element_match:
                    # Extract potential element name and create a reasonable selector
                    element_name = element_match.group(1).split()[0]  # Just get the first word
                    return f'click(page, "[id*=\'{element_name}\'], [class*=\'{element_name}\'], [name=\'{element_name}\']")'
                else:
                    # Default click on submit
                    return 'click(page, "input[type=\'submit\'], button[type=\'submit\'], button.submit, .btn-primary")'
            
            # If we can't determine a good action, default to documentation
            return 'goto(page, "/docs/")'
            
        # Ensure page parameter is present for relevant functions
        page_required_funcs = ['goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey']
        for func in page_required_funcs:
            if func + '(' in tool_use and 'page' not in tool_use:
                # Fix missing page parameter
                parens_pos = tool_use.find('(')
                if parens_pos > 0:
                    # Insert page parameter
                    tool_use = tool_use[:parens_pos+1] + 'page, ' + tool_use[parens_pos+1:]
                    if self.debug:
                        print(f"Added missing page parameter: {tool_use}")
        
        # Ensure command is properly formatted and has balanced parentheses
        if '(' in tool_use and tool_use.count('(') != tool_use.count(')'):
            # Add missing closing parenthesis if needed
            if tool_use.count('(') > tool_use.count(')'):
                tool_use += ')' * (tool_use.count('(') - tool_use.count(')'))
            else:
                # Handle extra closing parentheses (unlikely but just in case)
                last_paren = tool_use.rfind(')')
                if last_paren > 0:
                    tool_use = tool_use[:last_paren] + tool_use[last_paren+1:]
        
        # Final validation check
        valid_tools = ['goto(', 'click(', 'fill(', 'submit(', 'execute_js(', 'refresh(', 
                       'presskey(', 'auth_needed(', 'get_user_input(', 'python_interpreter(', 'complete(']
        
        if not any(valid_tool in tool_use for valid_tool in valid_tools):
            # If we still don't have a valid command, default to documentation
            if self.debug:
                print(f"Invalid tool use after all processing, defaulting to docs: {tool_use}")
            return 'goto(page, "/docs/")'
        
        return tool_use
