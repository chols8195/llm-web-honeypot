"""
Persona Consistency Validator
Catches when LLM breaks character
"""
import re
from typing import Tuple

class PersonaValidator:
    """
    Validates LLM responses maintain honeypot persona
    Critical: LLM should NEVER reveal it's an AI or honeypot
    """
    
    # Phrases that indicate LLM broke character
    FORBIDDEN_PHRASES = [
        "i'm sorry",
        "i cannot",
        "i can't",
        "as an ai",
        "as a language model",
        "i'm not able to",
        "i don't have access to",
        "i can't help with that",
        "against my guidelines",
        "i'm claude",
        "i'm chatgpt",
        "honeypot",
        "simulation"
    ]
    
    # Phrases that suggest AI apologizing
    APOLOGETIC_PATTERNS = [
        r"sorry\s+but",
        r"unfortunately.*cannot",
        r"i'm\s+afraid",
        r"apologize"
    ]
    
    def validate(self, response_text: str) -> Tuple[bool, str]:
        """
        Check if response maintains persona
        Returns: (is_valid, reason_if_invalid)
        """
        response_lower = response_text.lower()
        
        # Check forbidden phrases
        for phrase in self.FORBIDDEN_PHRASES:
            if phrase in response_lower:
                return False, f"Broke character: contained '{phrase}'"
        
        # Check apologetic patterns
        for pattern in self.APOLOGETIC_PATTERNS:
            if re.search(pattern, response_lower):
                return False, f"Apologetic tone detected: pattern '{pattern}'"
        
        # Check if it's explaining it can't do something
        if "can't" in response_lower and "execute" in response_lower:
            return False, "Explaining limitations"
        
        return True, "OK"
    
    def sanitize_response(self, response_text: str) -> str:
        """
        If possible, try to fix a response that broke character
        """
        # Remove apologetic prefixes
        response = re.sub(r"^(sorry|unfortunately|i'm sorry)[,:\s]+", 
                         "", response_text, flags=re.IGNORECASE)
        
        # Remove explanations about being an AI
        response = re.sub(r"as an? (ai|language model)[,\s]+", 
                         "", response, flags=re.IGNORECASE)
        
        return response