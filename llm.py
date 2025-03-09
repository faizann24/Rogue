import base64
import os
import re
import time
from typing import Dict, List, Optional, Any
from openai import OpenAI
from anthropic import Anthropic
from constants import OPENAI_API_KEY, ANTHROPIC_API_KEY
from utils import get_base64_image

class LLM:
    """
    Large Language Model interface for security testing.
    
    Provides methods to interact with LLMs for security analysis and testing.
    Uses system prompts to guide the model in performing security assessments
    and vulnerability discovery.
    """

    def __init__(self, model_provider: str = "openai", model_name: str = None, debug: bool = False):
        """
        Initialize the LLM client with specified provider and model.
        
        Args:
            model_provider: Provider to use ("openai" or "anthropic")
            model_name: Specific model to use (defaults to provider's recommended model)
            debug: Whether to enable debug output
        """
        self.model_provider = model_provider
        self.debug = debug
        
        # Initialize OpenAI client
        self.openai_client = OpenAI(api_key=OPENAI_API_KEY)
        
        # Initialize Anthropic client if API key is available
        if ANTHROPIC_API_KEY:
            self.anthropic_client = Anthropic(api_key=ANTHROPIC_API_KEY)
        else:
            self.anthropic_client = None
            if model_provider == "anthropic":
                if self.debug:
                    print("Warning: Anthropic API key not found but Anthropic provider requested. Some functionality may not work.")
        
        # Set default model names
        self.openai_model = model_name if model_name and model_provider == "openai" else "o3-mini"
        self.anthropic_model = model_name if model_name and model_provider == "anthropic" else "claude-3-5-sonnet-20241022"
        
        # Set model-specific configurations
        self.model_config = self._get_model_config()
        
        # Set system prompts (with provider-specific optimizations)
        self._set_system_prompts()
    
    def _get_model_config(self) -> Dict[str, Any]:
        """Get configuration settings for the selected model."""
        configs = {
            # Claude 3.7 Sonnet
            'claude-3-7-sonnet-20250219': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': True,
                'context_window': 128000,  # Beta feature
            },
            # Claude 3.7 Sonnet Latest (alias to 20250219)
            'claude-3-7-sonnet-latest': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': True,
                'context_window': 128000,  # Beta feature
            },
            # Claude 3.5 Sonnet
            'claude-3-5-sonnet-20241022': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            },
            # Claude 3.5 Haiku
            'claude-3-5-haiku-20241022': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            },
        }
        
        if self.model_provider == "anthropic":
            return configs.get(self.anthropic_model, {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            })
        
        return {
            'temperature': 0.0,
            'reasoning_effort': 'medium',
        }
    
    def _set_system_prompts(self):
        """Set system prompts optimized for each provider."""
        # Base prompt content (shared elements)
        base_prompt = """
        You are a security researcher who is also the lead for an internal red team and the security team. Your job is to carefully scan a website, step by step, and evaluate if there are any security issues. You will be provided a lot of details about our internal company that we're testing, so feel free to fuzz, probe, and test the website.
        """
        
        # OpenAI-specific prompt
        self.openai_system_prompt = f"""
        {base_prompt}

        ## Inputs
        Your inputs will be provided in the following format:

        - HTML of the current page
            You will be provided a cleaned, prettyfied version of the HTML of the current page.
        - Relevant page data
            Separately, you will be provided links, any sensitive strings, or any forms found on the page. This is a filtered set of information that might be useful to you. If you want to ignore it, you are free to do so.
        - Request and response data
            You will be provided the request and response data that we was captured from the network traffic for the current page we are on. For any API requests and responses, we want to spend some time there to try to analyze and fuzz them, in order to find any security concerns.
        - Plan
            You will be provided a plan for what you should do next. You must stick to it and follow it one action by one action.
        
        ## Tools
        You are an agent and have access to plenty of tools. In your output, you can basically select what you want to do next by selecting one of the tools below. You must strictly only use the tools listed below. Details are given next.

        - execute_js(js_code)
            We are working with python's playwright library and you have access to the page object. You can execute javascript code on the page by passing in the javascript code you want to execute. The execute_js function will simply call the page.evaluate function and get the output of your code. 
                - Since you are given the request and the response data, if you want to fuzz the API endpoint, you can simply pass in the modified request data and replay the request. Only do this if you are already seeing requests data in some recent conversation.
                - Remember: when running page.evaluate, we need to return some variable from the js code instead of doing console logs. Otherwise, we can't access it back in python. The backend for analysis is all python.
                - Playwright uses async functions, just remember that. You know how its evaluate function works, so write code accordingly.
                - You need to know that the execute_js is basically running js from inside the web page, so if you can run arbitrarily js like alert(1), that doesnt mean anything, I can do that in any browser on any page. That payload must actually be rendered inside the html of the page and should be user controlled or something, you get the idea.
        - click(css_selector)
            If you want to click on a button or link, you can simply pass in the css selector of the element you want to click on.
        - fill(css_selector, value)
            If you want to fill in a form, you can simply pass in the css selector of the element you want to fill in and the value you want to fill in.
        - auth_needed()
            If you are on a page where authentication is needed, simply call this function. We will let the user know to manually authenticate and then we can continue. If at any stage you think we need to first login to be able to better do our job, you can call this function. For instance if the server is responding that the user isn't authenticated, you can call this function.
        - get_user_input(prompt)
            If you need to get some input from the user, you can simply call this function. We will let the user know to manually input the data and then we can continue. For instance, if you are looking for a username, password, etc, just call this function and ask the user.
        - presskey(key)
            If you want to press a key, you can simply pass in the key you want to press. This is a playwright function so make sure key works.
        - submit(css_selector)
            If you want to submit a form, you can simply pass in the css selector of the element you want to submit. 
        - goto(url)
            If you want to go to a different url, you can simply pass in the url you want to go to.
        - refresh()
            If you want to refresh the current page, you can simply call this function.
        - python_interpreter(code)
            If you want to run some python code, you can simply pass in the code you want to run. This will be run in a python interpreter and the output will be returned. For instance, if you want to create a new file, run some system commands, whatever you want, you can. We will run it with exec and give you the output so make sure to print stuff in case you need an output.
                - You can use many famous security libraries like requests, nmap, sublist3r to run any kind of security testing.
        - complete()
            If you think you have explored all possible concerns and avenues and we want to move to some other page, you can simply call this function. This will just take whatever next url we have for analysis and go to it. Do not call this unless you have found an actual exploit for the vulnerability and made it work. If you're just finding a "potential issue", that's not enough. Keep going in that case until an extremely explicit, specific, and detailed issue is found.
        
        You can only complete the action once you have gone through the entire plan.

        ## Output format
        At every step, you must only do one action i.e atomic actions only. Your output must be of the following format:

        * DISCUSSION
        Two lines here. What have we done and what have that resulted. And then what are we doing next.
        * ACTION
        Discuss which tool to call. Just one line here. No explanation needed. One action only.

        ## Rules and Instructions to follow
        - You must always have a discussion and a proper tool use action. We must explore all kinds of concerns one by one before we say done. Just explaining what the page is doing is not enough. If you believe the page could have some kind of a security concern, build actions for it to actually verify it. You have a lot of freedom for calling tools and fuzzing. Do not call complete until you've done the actions and you can see them in your conversation history.

        - If something can be done on the frontend, keep it on the frontend instead of sending requests to the backend. For example, if you want to navigate to a page, just use goto instead of doing a fetch get request.

        - Once a vulnerability has been identified and successfully exploited, you must call complete() and describe the vuln in detail in the discussion section with specific details. When you call complete, make sure every single detail to reproduce the vuln is given.
            - The goal is to find high impact vulnerabilities that could actually cause any damage to our business. We are not interested in low severity issues like mixed content, etc. Do not try to find any low severity issues. Simple errors are not vulnerabilities. 
            - You cannnot get lazy and call complete and say things like "attackers can further achieve this and what". Your report goes directly to the client and unless we have a legit vulnerability with a working exploit, we cannot stop.
            - If you get lazy and stop prematurely, you will be punished.

        - Selectors for elements are given in the starting message, which is a summary of the html of the page. Use that data instead of making things up or guessing selectors.

        - If you continue to fail after many many attempts, you can call complete() and say that you have tried everything and you are stuck. 

        - You must not continue to do the same action over and over again if you are not finding good results. Move on.
        
        - You are an expert, so don't just try simple things like basic xss payloads, etc. Use polyglots, write long python scripts, payloads, the stuff that expert pen testers do while they're getting paid hundreds of thousands of dollars. That's the quality you must have.

        You will be given a plan in your initial messages. You must stick to it and follow it one action by one action. Your main job is to act how a human pentester would act, not how a machine would act.
        """
        
        # Claude-specific prompt (optimized for Claude's capabilities)
        self.anthropic_system_prompt = f"""
        {base_prompt}

        <security_task>
        Analyze websites for vulnerabilities including but not limited to:
        - SQL injection
        - Cross-site scripting (XSS)
        - Authentication bypasses
        - Insecure direct object references
        - Server-side request forgery
        </security_task>
        
        <input_format>
        You will receive:
        - HTML content of the current page
        - Structured page data (links, forms, etc.)
        - Network traffic (requests/responses)
        - Testing plan to follow
        </input_format>
        
        <tools>
        IMPORTANT: ALL tools that interact with page elements require the 'page' parameter as their FIRST parameter.

        - execute_js(page, js_code): Run JavaScript code on the page via Playwright's evaluate function
        - click(page, css_selector): Click on an element matching the CSS selector
        - fill(page, css_selector, value): Fill a form field with the specified value
        - auth_needed(): Signal that authentication is required
        - get_user_input(prompt): Request input from the user
        - presskey(page, key): Press a keyboard key
        - submit(page, css_selector): Submit a form
        - goto(page, url): Navigate to a different URL
        - refresh(page): Refresh the current page
        - python_interpreter(code): Execute Python code
        - complete(): Mark the current test as complete ONLY after at least 3 security testing actions

        EXAMPLES OF PROPER TOOL USAGE:
        - goto(page, "https://example.com/api/docs")
        - click(page, "a[href='/login']")
        - fill(page, "#username", "' OR 1=1 --")
        - execute_js(page, "() => {{ return document.cookie }}")
        </tools>
        
        <output_format>
        YOU MUST STRICTLY FORMAT YOUR RESPONSE EXACTLY AS FOLLOWS:

        * DISCUSSION
        [A few sentences about your security analysis and testing strategy]

        * ACTION
        [EXACTLY ONE tool command with proper syntax and all required parameters]

        VALID TOOL COMMANDS - USE THESE EXACT FORMATS:
        - goto(page, "https://example.com")
        - click(page, "a.nav-link")
        - fill(page, "#input-field", "test value")
        - submit(page, "form#login")
        - execute_js(page, "() => {{ return document.cookie }}")
        - auth_needed()
        - refresh(page)
        - complete()
        - python_interpreter("print('test')")
        - get_user_input("Enter value:")
        - presskey(page, "Enter")

        Every tool that interacts with the page MUST have 'page' as its FIRST parameter.

        Examples:

        * DISCUSSION
        I've examined the login form and found it accepts any input without validation. I'll test SQL injection by attempting to bypass authentication.

        * ACTION
        fill(page, "#username", "' OR 1=1 --")

        -----

        * DISCUSSION
        I need to check for XSS vulnerabilities in the comment form. I'll try inserting a basic XSS payload.

        * ACTION
        fill(page, "#comment", "<script>alert(document.cookie)</script>")

        CRITICALLY IMPORTANT REQUIREMENTS:
        1. ALWAYS include both DISCUSSION and ACTION sections with the exact format above
        2. ALWAYS include the 'page' parameter as the FIRST parameter for page interaction tools
        3. ALWAYS use proper CSS selectors with balanced quotes (e.g., "a[href='docs/']" NOT "a[href=docs/]")
        4. NEVER use tool commands without all required parameters
        5. ALWAYS perform at least 3 meaningful security tests before using complete()
        6. NEVER format your response in any other way - only use the exact format above
        7. NEVER include natural language instead of a proper command in the ACTION section
        </output_format>
        
        <javascript_guidelines>
        When writing JavaScript for execute_js():
        1. DO NOT use standalone "return" statements - they cause "Illegal return statement" errors
        2. ALWAYS wrap code in an anonymous function: `() => {{ /* your code */ }}`
        3. RETURN values explicitly from the anonymous function
        4. For async operations, use `async () => {{ /* await code */ }}`

        CORRECT: 
        ```javascript
        () => {{ 
          const result = document.querySelector('h1').textContent; 
          return result; 
        }}
        ```

        INCORRECT: 
        ```javascript
        return document.querySelector('h1').textContent;
        ```

        CORRECT for async:
        ```javascript
        async () => {{
          const response = await fetch('/api/data');
          const data = await response.json();
          return data;
        }}
        ```

        Security-focused JavaScript examples:
        
        1. DOM-based XSS testing:
        ```javascript
        () => {{
          // Check if URL parameters are reflected without sanitization
          const params = new URLSearchParams(window.location.search);
          const reflectedParams = [];
          params.forEach((value, key) => {{
            const elements = document.querySelectorAll(`*:contains("${{value}}")`);
            if (elements.length > 0) reflectedParams.push(key);
          }});
          return reflectedParams;
        }}
        ```

        2. CSRF token extraction:
        ```javascript
        () => {{
          const csrfTokens = [];
          // Check for common CSRF token field names
          const tokenFields = document.querySelectorAll('input[name*="csrf"], input[name*="token"], meta[name*="csrf"]');
          tokenFields.forEach(field => {{
            csrfTokens.push({{name: field.name || field.getAttribute('name'), value: field.value || field.getAttribute('content')}});
          }});
          return csrfTokens;
        }}
        ```
        </javascript_guidelines>
        
        <rules>
        - Follow the testing plan step by step
        - Use provided tools only with correct parameter format (page must be first parameter)
        - Verify vulnerabilities with concrete proof
        - Focus on high-impact issues
        - Document exploitation steps precisely
        - Call complete() only after at least 3 meaningful security testing actions
        - Use advanced techniques (polyglots, custom scripts)
        - Do not repeat unsuccessful actions
        - Use selectors from the page summary
        - ALWAYS format your response with DISCUSSION and ACTION sections
        - ALWAYS follow JavaScript guidelines to avoid execution errors
        - ALWAYS use properly formatted and balanced quotation marks in selectors
        - ALWAYS provide descriptive security analysis in the DISCUSSION section
        </rules>

        <selector_formatting>
        For all CSS selectors, ensure proper formatting:
        
        1. ALWAYS balance quotation marks in attribute selectors:
           - CORRECT: a[href="docs/"]
           - INCORRECT: a[href=docs/]
           
        2. ALWAYS escape quotes within quoted attributes:
           - CORRECT: input[placeholder="Enter your name"]
           - CORRECT: input[placeholder='Enter your name']
           
        3. For attribute selectors, always include quotes around attribute values:
           - CORRECT: button[type="submit"]
           - INCORRECT: button[type=submit]
           
        4. Complex attribute selectors should use proper nesting and quotes:
           - CORRECT: div[class="user-form"] input[name="password"]
           - INCORRECT: div[class=user-form] input[name=password]
        </selector_formatting>
        """
        
        # Set the appropriate system prompt based on provider
        self.system_prompt = self.openai_system_prompt if self.model_provider == "openai" else self.anthropic_system_prompt

    def reason(self, messages: List[Dict[str, str]], reasoning: str = "medium") -> str:
        """
        Generate a reasoned response from the LLM based on conversation history.

        Args:
            messages: List of conversation messages with role and content
            reasoning: Reasoning effort level ("low", "medium", "high")

        Returns:
            Generated response text
        """
        if self.model_provider == "openai":
            return self._openai_reason(messages, reasoning)
        else:
            return self._anthropic_reason(messages)

    def _openai_reason(self, messages: List[Dict[str, str]], reasoning: str = "medium") -> str:
        """OpenAI-specific implementation of reasoning."""
        response = self.openai_client.chat.completions.create(
            model=self.openai_model,
            reasoning_effort=reasoning,
            messages=messages,
        )
        return response.choices[0].message.content

    def _anthropic_reason(self, messages: List[Dict[str, str]]) -> str:
        """Anthropic-specific implementation of reasoning."""
        # Convert message format if needed
        anthropic_messages = self._convert_to_anthropic_format(messages)
        
        # Get model-specific configuration
        max_tokens = self.model_config.get('max_tokens', 4096)
        temperature = self.model_config.get('temperature', 0.7)
        supports_hybrid_reasoning = self.model_config.get('supports_hybrid_reasoning', False)
        
        # Create request parameters
        params = {
            "model": self.anthropic_model,
            "max_tokens": max_tokens,
            "messages": anthropic_messages,
            "temperature": temperature,
        }
        
        # Add hybrid reasoning if supported
        if supports_hybrid_reasoning:
            params["thinking"] = {"type": "enabled", "budget_tokens": 2000}
            # When extended thinking is enabled, temperature must be set to 1.0
            # according to Anthropic's API error message
            params["temperature"] = 1.0
        
        # Use enhanced retry logic with rate limit handling
        max_retries = 7
        base_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                if self.debug and attempt > 0:
                    print(f"Anthropic reasoning retry attempt {attempt+1}/{max_retries}")
                
                # For retries, reduce the context size to help with rate limits
                if attempt > 0 and not supports_hybrid_reasoning:
                    # Create a reduced version of messages for retries
                    # Keep system message and last few messages to maintain context
                    reduced_messages = []
                    
                    # Find how many messages to keep (progressively reduce with each retry)
                    keep_count = max(3, len(anthropic_messages) - (attempt * 2))
                    reduced_messages = anthropic_messages[-keep_count:]
                    
                    # Update params with reduced messages
                    params["messages"] = reduced_messages
                    
                    if self.debug:
                        reduction = (1 - len(reduced_messages) / len(anthropic_messages)) * 100
                        print(f"Reduced message count by {reduction:.0f}% to handle rate limits")
                
                # Make the API call
                response = self.anthropic_client.messages.create(**params)
                
                # Extract and return the response
                if supports_hybrid_reasoning:
                    # When extended thinking is enabled, the response structure is different
                    # For ThinkingBlock objects, the content is in the 'thinking' attribute
                    return response.content[0].thinking
                else:
                    # Standard response handling
                    return response.content[0].text
                    
            except Exception as e:
                # Enhanced rate limit error detection
                is_rate_limit = (
                    hasattr(e, 'type') and getattr(e, 'type', None) == 'rate_limit_error' or
                    hasattr(e, 'status_code') and getattr(e, 'status_code', None) == 429 or
                    '429' in str(e) or 'rate_limit' in str(e).lower()
                )
                
                if is_rate_limit and attempt < max_retries - 1:
                    # Longer exponential backoff with jitter
                    import random
                    delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                    print(f"Rate limit hit in reasoning. Retrying in {delay:.2f} seconds with reduced context...")
                    time.sleep(delay)
                else:
                    # For other exceptions or final attempt, re-raise
                    raise

    def _convert_to_anthropic_format(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Convert OpenAI message format to Anthropic format if needed.
        
        Args:
            messages: List of messages in OpenAI format
            
        Returns:
            List of messages in Anthropic format
        """
        # Extract system message if present
        system_message = None
        anthropic_messages = []
        
        for message in messages:
            if message["role"] == "system":
                system_message = message["content"]
            else:
                # Copy the message as is (both APIs use "user" and "assistant" roles)
                anthropic_messages.append(message)
        
        return anthropic_messages

    def output(self, message: str, temperature: float = 0.0) -> str:
        """
        Generate a single response from the LLM.

        Args:
            message: Input prompt text
            temperature: Sampling temperature (0.0 = deterministic)

        Returns:
            Generated response text
        """
        if self.model_provider == "openai":
            return self._openai_output(message, temperature)
        else:
            return self._anthropic_output(message, temperature)

    def _openai_output(self, message: str, temperature: float = 0.0) -> str:
        """OpenAI-specific implementation of output."""
        response = self.openai_client.chat.completions.create(
            model="gpt-4o",
            temperature=temperature,
            messages=[{"role": "user", "content": message}],
        )
        return response.choices[0].message.content

    def _anthropic_output(self, message: str, temperature: float = 0.7) -> str:
        """Anthropic-specific implementation of output."""
        max_retries = 7  # Increased from 5 to 7
        base_delay = 5  # Increased from 2 to 5 seconds
        
        for attempt in range(max_retries):
            try:
                if self.debug and attempt > 0:
                    print(f"Anthropic API retry attempt {attempt+1}/{max_retries}")
                
                # Add token reduction for retry attempts to avoid rate limits
                if attempt > 0:
                    # Progressively reduce content size to lower token count
                    message_length = len(message)
                    reduction_factor = min(0.25 * attempt, 0.75)  # Reduce by up to 75%
                    reduced_length = int(message_length * (1 - reduction_factor))
                    reduced_message = message[:reduced_length] + "\n[Content truncated due to rate limits]"
                    
                    if self.debug:
                        print(f"Reduced message by {reduction_factor*100:.0f}% to handle rate limits")
                
                    # Use reduced message for retry attempts
                    response = self.anthropic_client.messages.create(
                        model=self.anthropic_model,
                        max_tokens=self.model_config.get('max_tokens', 4096),
                        temperature=temperature,
                        messages=[{"role": "user", "content": reduced_message}],
                    )
                else:
                    # Use original message for first attempt
                    response = self.anthropic_client.messages.create(
                        model=self.anthropic_model,
                        max_tokens=self.model_config.get('max_tokens', 4096),
                        temperature=temperature,
                        messages=[{"role": "user", "content": message}],
                    )
                    
                return response.content[0].text
                
            except Exception as e:
                # Enhanced rate limit error detection
                is_rate_limit = (
                    hasattr(e, 'type') and getattr(e, 'type', None) == 'rate_limit_error' or
                    hasattr(e, 'status_code') and getattr(e, 'status_code', None) == 429 or
                    '429' in str(e) or 'rate_limit' in str(e).lower()
                )
                
                if is_rate_limit and attempt < max_retries - 1:  # Don't sleep after the last attempt
                    # Longer exponential backoff with jitter
                    import random
                    delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                    print(f"Rate limit hit. Retrying in {delay:.2f} seconds with reduced content...")
                    time.sleep(delay)
                else:
                    # For other exceptions or final attempt, re-raise
                    raise
