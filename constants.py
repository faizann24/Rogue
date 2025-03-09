import os

# OpenAI API key
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
# Note: We don't raise an error here to allow testing without an API key
# if not OPENAI_API_KEY:
#     raise ValueError("OpenAI API key not found. Please set the OPENAI_API_KEY environment variable.")

# Anthropic API key
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
# Note: We don't raise an error here to allow using OpenAI models without an Anthropic API key
