from llm import LLM


class Summarizer:
    def __init__(self, model_provider: str = "openai", model_name: str = None, debug: bool = False):
        """
        Initialize Summarizer with LLM instance.
        
        Args:
            model_provider: Provider to use ("openai" or "anthropic")
            model_name: Specific model to use (defaults to provider's recommended model)
            debug: Whether to enable debug output
        """
        self.debug = debug
        self.llm = LLM(model_provider=model_provider, model_name=model_name, debug=debug)

    def summarize(self, llm_response, tool_use, tool_output):
        prompt = f"""
        You are a summarizer agent. Your job is to analyze and summarize the following information:

        1. LLM Agent Response: This is what the agent was trying to do
        {llm_response}

        2. Tool Use: This is the actual command that was executed
        {tool_use}

        3. Tool Output: This is what we got back from executing the command
        {tool_output[:100000]}

        Please provide a concise one-paragraph summary that explains:
        - What the agent was attempting to do
        - What command was actually executed
        - What the result was and if it was successful

        If the tool output is less than 200 words, you can return it as-is.
        If it's longer than 200 words, summarize it while preserving key information and technical details.

        Focus on security-relevant details and any potential findings or issues discovered.

        The summary should be 2 sentences at min, 4 at max. Keep specific/technical details in the summary. If not needed, don't make it long. Succint and to the point.
        """
        return self.llm.output(prompt)

    def summarize_conversation(self, conversation):
        # Convert conversation list to string format
        conversation_str = "\n".join([f"{msg['role']}: {msg['content']}" for msg in conversation])
        
        prompt = f"""
        You are a summarizer agent. Your job is to summarize the following conversation:

        {conversation_str}

        Please provide a bullet point summary that includes:
        - What security tests were attempted
        - What specific commands/payloads were used
        - What the results of each test were
        - Any potential security findings discovered

        Keep the summary focused on technical details and actual actions taken. Each bullet point should be 1-2 sentences max. Keep the overall summary short.
        """

        output = self.llm.output(prompt)
        output = "To reduce context, here is a summary of the previous part of the conversation:\n" + output
        return [{"role": "user", "content": output}]

    def summarize_page_source(self, page_source, url):
        """
        Summarize page source with chunking for large pages.
        
        For large pages, breaks content into chunks and summarizes each chunk
        separately, then combines the results into a final summary.
        
        Args:
            page_source: HTML content of the page
            url: URL of the page
            
        Returns:
            Structured summary of the page
        """
        # Default chunk size (characters) - approximately 5K tokens
        chunk_size = 20000
        
        # If page source is small enough, process it directly
        if len(page_source) <= chunk_size:
            return self._summarize_page_chunk(page_source, url)
        
        # For large pages, use a chunking approach
        chunks = [page_source[i:i+chunk_size] for i in range(0, len(page_source), chunk_size)]
        
        if self.debug:
            print(f"Page source is large. Breaking into {len(chunks)} chunks for processing.")
        
        # Process each chunk
        chunk_summaries = []
        for i, chunk in enumerate(chunks):
            if self.debug:
                print(f"Processing chunk {i+1}/{len(chunks)}")
            
            # Create a focused prompt for this chunk
            chunk_summary = self._summarize_page_chunk(
                chunk,
                f"{url} (part {i+1}/{len(chunks)})"
            )
            chunk_summaries.append(chunk_summary)
        
        # Combine chunk summaries
        if len(chunk_summaries) > 1:
            combined_prompt = f"""
            You are a summarizer agent. Your job is to combine the following partial summaries 
            of the same web page into a single coherent summary. URL: {url}
            
            Each part represents a different section of the same page:
            
            {' '.join(chunk_summaries)}
            
            Please create a unified structured summary with the following sections:
            
            1. Page Overview
            - Brief 2-3 sentence description of what this page does/contains
            - Main functionality and purpose
            
            2. Important Interactive Elements
            - Links: List key links with their text, and their href
            - Forms: List forms with their purpose and CSS selectors for the form and key inputs
            - Buttons: List important buttons with their purpose and CSS selectors
            - Input fields: List important input fields with their purpose and CSS selectors
            
            3. Dynamic Elements
            - List any AJAX endpoints or API calls found
            - Note any JavaScript event handlers or dynamic content loading
            - Identify any state changes or dynamic updates
            
            4. Security-Relevant Items
            - Authentication/authorization elements
            - File upload capabilities
            - API endpoints
            - Form submissions
            - User input fields
            
            Deduplicate elements and ensure the summary is coherent. Prioritize security-relevant elements.
            """
            return self.llm.output(combined_prompt)
        else:
            # If there was only one chunk, just return that summary
            return chunk_summaries[0]
    
    def _summarize_page_chunk(self, page_chunk, context):
        """
        Summarize a single chunk of page source.
        
        Args:
            page_chunk: A portion of the page's HTML content
            context: Description of what this chunk represents
            
        Returns:
            Structured summary of the chunk
        """
        prompt = f"""
        You are a summarizer agent. Your job is to analyze and summarize the following page source from: {context}
        
        {page_chunk}
        
        Please provide a structured summary with the following sections:
        
        1. Page Overview
        - Brief 2-3 sentence description of what this page does/contains
        - Main functionality and purpose
        
        2. Important Interactive Elements
        - Links: List key links with their text, and their href
        - Forms: List forms with their purpose and CSS selectors for the form and key inputs
        - Buttons: List important buttons with their purpose and CSS selectors
        - Input fields: List important input fields with their purpose and CSS selectors
        
        3. Dynamic Elements
        - List any AJAX endpoints or API calls found
        - Note any JavaScript event handlers or dynamic content loading
        - Identify any state changes or dynamic updates
        
        4. Security-Relevant Items
        - Authentication/authorization elements
        - File upload capabilities
        - API endpoints
        - Form submissions
        - User input fields
        
        For each element, provide:
        1. A brief description of its purpose/functionality
        2. The exact CSS selector to target it
        3. Any relevant attributes or properties
        
        Keep the summary focused and technical. Prioritize elements that are security-relevant or core to the page's functionality.
        """
        return self.llm.output(prompt)
