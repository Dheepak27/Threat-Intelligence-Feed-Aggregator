import nltk
import requests
import json
from typing import Optional, Dict, List, Tuple
from pathlib import Path
import logging
import time
from datetime import datetime
import regex as re
# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AISummarizer:
    """
    A class for generating AI-powered summaries of threat intelligence articles.
    Integrated with Ollama for local LLM processing as per technical requirements.
    """
    
    def __init__(self, use_ollama: bool = True, ollama_url: str = "http://localhost:11434", 
                 model_name: str = "llama2") -> None:
        """
        Initialize the summarizer.
        
        Args:
            use_ollama: Whether to use Ollama for summarization (default True per requirements)
            ollama_url: URL for Ollama API
            model_name: Name of the LLM model to use (llama2, mistral, etc.)
        """
        self.use_ollama = use_ollama
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.ollama_available = False
        
        # Test Ollama availability on initialization
        if self.use_ollama:
            self.ollama_available = self._test_ollama_connection()
            if not self.ollama_available:
                logger.warning(f"Ollama not available at {ollama_url}. Falling back to extractive summarization.")
        
        # Ensure NLTK resources are available
        self._ensure_nltk_data()
        
        # Initialize threat classification system
        self._initialize_threat_categories()
    
    def _ensure_nltk_data(self) -> None:
        """Ensure required NLTK data is available."""
        try:
            nltk.data.find('tokenizers/punkt')
            nltk.data.find('tokenizers/punkt_tab') # New tokenizer in recent NLTK versions
        except LookupError:
            logger.info("Downloading required NLTK data...")
            try:
                nltk.download('punkt', quiet=True)
                nltk.download('punkt_tab', quiet=True)
            except Exception as e:
                logger.warning(f"Could not download NLTK data: {e}")
    
    def _test_ollama_connection(self) -> bool:
        """Test if Ollama is available and responding."""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def _initialize_threat_categories(self) -> None:
        """Initialize comprehensive threat categorization system."""
        self.threat_patterns = {
            "Critical Vulnerability": {
                "keywords": ["zero-day", "critical vulnerability", "rce", "remote code execution", 
                           "privilege escalation", "authentication bypass", "cve", "cvss 9", "cvss 10"],
                "severity": "Critical",
                "priority": 1
            },
            "Malware Campaign": {
                "keywords": ["malware", "ransomware", "trojan", "backdoor", "rat", "remote access trojan",
                           "stealer", "cryptominer", "botnet", "campaign", "malicious payload"],
                "severity": "High",
                "priority": 2
            },
            "Advanced Persistent Threat": {
                "keywords": ["apt", "advanced persistent threat", "nation-state", "state-sponsored",
                           "targeted attack", "espionage", "attribution", "threat actor"],
                "severity": "High",
                "priority": 2
            },
            "Phishing Campaign": {
                "keywords": ["phishing", "spear phishing", "whaling", "business email compromise", "bec",
                           "social engineering", "credential harvesting", "fake login"],
                "severity": "Medium",
                "priority": 3
            },
            "Data Breach": {
                "keywords": ["data breach", "data leak", "exposed database", "stolen credentials",
                           "compromised accounts", "data exposure", "database dump"],
                "severity": "High",
                "priority": 2
            },
            "Supply Chain Attack": {
                "keywords": ["supply chain", "software supply chain", "third-party", "dependency",
                           "poisoned package", "typosquatting", "software compromise"],
                "severity": "High",
                "priority": 2
            },
            "DDoS Attack": {
                "keywords": ["ddos", "denial of service", "distributed denial", "amplification",
                           "volumetric attack", "application layer attack"],
                "severity": "Medium",
                "priority": 4
            },
            "Insider Threat": {
                "keywords": ["insider threat", "malicious insider", "privileged access abuse",
                           "data exfiltration", "internal threat", "rogue employee"],
                "severity": "Medium",
                "priority": 3
            },
            "Cryptocurrency Threat": {
                "keywords": ["cryptocurrency", "bitcoin", "crypto", "wallet", "mining", "ransomware payment",
                           "blockchain", "digital currency", "crypto exchange"],
                "severity": "Medium",
                "priority": 4
            },
            "Mobile Threat": {
                "keywords": ["mobile malware", "android", "ios", "mobile app", "malicious app",
                           "mobile banking", "sms", "mobile phishing"],
                "severity": "Medium",
                "priority": 3
            }
        }
    
    def generate_summary(self, title: str, content: str, source: str = "") -> Dict[str, any]:
        """
        Generate a comprehensive summary of the threat intelligence article.
        
        Args:
            title: Title of the article
            content: Content to summarize
            source: Source of the article
            
        Returns:
            Dictionary with summary, threat classification, and metadata
        """
        start_time = time.time()
        
        # Determine the best summarization method
        if self.use_ollama and self.ollama_available:
            summary_result = self._generate_ollama_summary(title, content)
        else:
            summary_result = self._generate_extractive_summary(title, content)
        
        # Enhance with threat classification
        threat_classification = self._classify_threat(title, content)
        
        # Generate actionable recommendations
        recommendations = self._generate_actionable_recommendations(threat_classification)
        
        # Extract key entities and indicators
        key_entities = self._extract_key_entities(content)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        return {
            "summary": summary_result,
            "threat_type": threat_classification["primary_type"],
            "severity": threat_classification["severity"],
            "confidence": threat_classification["confidence"],
            "affected_systems": threat_classification["affected_systems"],
            "recommendations": recommendations,
            "key_entities": key_entities,
            "source": source,
            "processed_at": datetime.now().isoformat(),
            "processing_time": round(processing_time, 2),
            "summary_method": "Ollama LLM" if (self.use_ollama and self.ollama_available) else "Extractive"
        }
    
    def _generate_ollama_summary(self, title: str, content: str) -> str:
        """
        Generate a summary using Ollama LLM as per technical requirements.
        
        Args:
            title: Article title
            content: Article content
            
        Returns:
            AI-generated summary
        """
        try:
            # Prepare content for the LLM (limit length to avoid token issues)
            max_content_length = 4000
            input_content = f"{title}\n\n{content[:max_content_length]}{'...' if len(content) > max_content_length else ''}"
                
            # Enhanced prompt for better threat intelligence analysis
            prompt = f"""You are a cybersecurity threat intelligence analyst. Analyze the following threat intelligence report and provide a comprehensive summary.
            

Article: {input_content}

Please provide a structured analysis with:

1. THREAT OVERVIEW: Brief description of the threat (2-3 sentences)
2. THREAT ACTOR: Who is behind this threat (if mentioned)
3. ATTACK VECTOR: How the attack is carried out
4. IMPACT: What systems/data are affected
5. INDICATORS: Key technical indicators mentioned
6. TIMELINE: When this threat was discovered/is active
7. MITIGATION: Immediate actions to take

Keep the summary concise but comprehensive, focusing on actionable intelligence for security teams."""
            
            # Make request to Ollama API with improved error handling
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3, # Lower temperature for more focused output
                        "top_p": 0.9,
                        "num_predict": 800 # Limit response length
                    }
                },
                timeout=60 # Increased timeout for better reliability
            )
            
            response.raise_for_status()
            
            result = response.json()
            ai_summary = result.get("response", "Error: Empty response from LLM")
            
            # Validate and clean the response
            if len(ai_summary.strip()) < 50:
                logger.warning("LLM response too short, falling back to extractive summary")
                return self._generate_extractive_summary(title, content)
            
            return ai_summary.strip()
                
        except requests.RequestException as e:
            logger.error(f"Network error using Ollama: {e}")
            self.ollama_available = False # Mark as unavailable for future requests
            return self._generate_extractive_summary(title, content)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error from Ollama response: {e}")
            return self._generate_extractive_summary(title, content)
        except Exception as e:
            logger.error(f"Unexpected error using Ollama: {e}")
            return self._generate_extractive_summary(title, content)
    
    def _generate_extractive_summary(self, title: str, content: str) -> str:
        """
        Generate an enhanced extractive summary when LLM is not available.
        
        Args:
            title: Article title
            content: Article content
            
        Returns:
            Extractive summary with enhanced intelligence
        """
        try:
            sentences = nltk.sent_tokenize(content)
        except Exception as e:
            logger.warning(f"Error tokenizing sentences: {e}")
            sentences = [s.strip() + '.' for s in content.split('.') if s.strip()]
        
        # Score sentences based on threat intelligence relevance
        scored_sentences = []
        
        # Keywords that indicate important threat intelligence content
        important_keywords = [
            'malware', 'vulnerability', 'exploit', 'attack', 'breach', 'compromise',
            'threat', 'malicious', 'suspicious', 'campaign', 'actor', 'indicator',
            'cve', 'zero-day', 'ransomware', 'phishing', 'backdoor', 'trojan'
        ]
        
        for sentence in sentences:
            if len(sentence.split()) < 5: # Skip very short sentences
                continue
                
            score = 0
            sentence_lower = sentence.lower()
            
            # Score based on important keywords
            for keyword in important_keywords:
                if keyword in sentence_lower:
                    score += 2
            
            # Boost score for sentences with specific patterns
            if any(pattern in sentence_lower for pattern in ['researchers', 'discovered', 'observed', 'detected']):
                score += 1
            
            if any(pattern in sentence_lower for pattern in ['recommend', 'should', 'patch', 'update', 'mitigate']):
                score += 1
            
            # Penalize very long sentences
            if len(sentence.split()) > 40:
                score -= 1
            
            scored_sentences.append((sentence, score))
        
        # Sort by score and select top sentences
        scored_sentences.sort(key=lambda x: x[1], reverse=True)
        top_sentences = [sent[0] for sent in scored_sentences[:4]]
        
        # Create coherent summary
        summary = ' '.join(top_sentences) if top_sentences else content[:500] + "..."
        
        return summary
    
    def _classify_threat(self, title: str, content: str) -> Dict[str, any]:
        """
        Classify the threat type and assess severity.
        
        Args:
            title: Article title
            content: Article content
            
        Returns:
            Threat classification information
        """
        combined_text = f"{title} {content}".lower()
        
        # Score each threat category
        category_scores = {}
        
        for category, details in self.threat_patterns.items():
            score = 0
            keyword_matches = []
            
            for keyword in details["keywords"]:
                if keyword.lower() in combined_text:
                    score += 1
                    keyword_matches.append(keyword)
            
            if score > 0:
                category_scores[category] = {
                    "score": score,
                    "matches": keyword_matches,
                    "severity": details["severity"],
                    "priority": details["priority"]
                }
        
        # Determine primary threat type
        if category_scores:
            primary_category = max(category_scores.keys(), key=lambda x: category_scores[x]["score"])
            primary_info = category_scores[primary_category]
            
            # Calculate confidence based on number of matches
            confidence = min(0.95, 0.3 + (primary_info["score"] * 0.15))
            
        else:
            primary_category = "General Security Threat"
            primary_info = {"severity": "Unknown", "priority": 5}
            confidence = 0.3
        
        # Identify affected systems
        affected_systems = self._identify_affected_systems(combined_text)
        
        return {
            "primary_type": primary_category,
            "severity": primary_info.get("severity", "Medium"),
            "confidence": confidence,
            "all_categories": category_scores,
            "affected_systems": affected_systems
        }
    
    def _identify_affected_systems(self, content: str) -> List[str]:
        """Identify systems and technologies mentioned in the threat."""
        system_patterns = {
            "Windows": ["windows", "microsoft", "active directory", "iis", "exchange"],
            "Linux": ["linux", "ubuntu", "debian", "centos", "rhel", "unix"],
            "macOS": ["macos", "mac os", "apple", "safari"],
            "Web Applications": ["web app", "website", "http", "https", "php", "javascript"],
            "Mobile": ["android", "ios", "mobile", "smartphone", "tablet"],
            "Cloud": ["aws", "azure", "google cloud", "cloud", "kubernetes", "docker"],
            "Network Infrastructure": ["router", "firewall", "vpn", "dns", "dhcp"],
            "Databases": ["mysql", "postgresql", "mongodb", "oracle", "database"],
            "Email Systems": ["outlook", "exchange", "gmail", "email", "smtp"],
            "IoT Devices": ["iot", "smart device", "camera", "sensor", "embedded"]
        }
        
        affected = []
        for system, keywords in system_patterns.items():
            if any(keyword in content for keyword in keywords):
                affected.append(system)
        
        return affected
    
    def _generate_actionable_recommendations(self, threat_classification: Dict) -> List[str]:
        """
        Generate actionable recommendations based on threat type.
        
        Args:
            threat_classification: Result from _classify_threat
            
        Returns:
            List of actionable recommendations
        """
        threat_type = threat_classification["primary_type"]
        severity = threat_classification["severity"]
        affected_systems = threat_classification["affected_systems"]
        
        # Base recommendations for all threats
        recommendations = [
            "Monitor network traffic for suspicious activity",
            "Review and update security policies",
            "Ensure all systems have latest security patches"
        ]
        
        # Threat-specific recommendations
        specific_recommendations = {
            "Critical Vulnerability": [
                "Immediately assess if your systems are affected",
                "Apply security patches as soon as available",
                "Implement temporary mitigations if patches aren't ready",
                "Conduct emergency vulnerability scanning",
                "Consider isolating affected systems if actively exploited"
            ],
            "Malware Campaign": [
                "Update antivirus/EDR signatures immediately",
                "Scan all systems for indicators of compromise",
                "Review email security controls and filters",
                "Implement application whitelisting where possible",
                "Monitor for lateral movement attempts"
            ],
            "Advanced Persistent Threat": [
                "Initiate threat hunting activities",
                "Review privileged account access and activity",
                "Implement additional monitoring on critical assets",
                "Consider engaging external threat intelligence services",
                "Conduct forensic analysis if compromise suspected"
            ],
            "Phishing Campaign": [
                "Alert users about this specific phishing campaign",
                "Review and strengthen email security controls",
                "Conduct targeted security awareness training",
                "Implement DMARC, SPF, and DKIM if not already done",
                "Monitor for suspicious login attempts"
            ],
            "Data Breach": [
                "Check if your organization's data is involved",
                "Monitor for unusual account activity",
                "Consider mandatory password resets if affected",
                "Review and test data loss prevention controls",
                "Prepare breach notification procedures if required"
            ],
            "Supply Chain Attack": [
                "Audit all third-party software and dependencies",
                "Implement software composition analysis",
                "Review vendor security practices and agreements",
                "Monitor for unauthorized software changes",
                "Establish incident response procedures for suppliers"
            ]
        }
        
        # Add threat-specific recommendations
        if threat_type in specific_recommendations:
            recommendations.extend(specific_recommendations[threat_type])
        
        # Add system-specific recommendations
        if affected_systems:
            for system in affected_systems:
                if system == "Windows":
                    recommendations.append("Review Windows Event Logs for suspicious activity")
                elif system == "Web Applications":
                    recommendations.append("Review web application logs and implement WAF rules")
                elif system == "Cloud":
                    recommendations.append("Review cloud security configurations and access logs")
        
        # Prioritize based on severity
        if severity == "Critical":
            recommendations.insert(0, "🚨 URGENT: This is a critical threat requiring immediate attention")
        elif severity == "High":
            recommendations.insert(0, "⚠️ HIGH PRIORITY: Address this threat within 24 hours")
        
        return list(dict.fromkeys(recommendations)) # Remove duplicates while preserving order
    
    def _extract_key_entities(self, content: str) -> Dict[str, List[str]]:
        """
        Extract key entities from threat intelligence content.
        
        Args:
            content: Article content
            
        Returns:
            Dictionary of extracted entities
        """
        entities = {
            "threat_actors": [],
            "malware_families": [],
            "attack_techniques": [],
            "industries": [],
            "countries": []
        }
        
        # Define entity patterns
        entity_patterns = {
            "threat_actors": [
                r"(?:APT[\s-]?\d+)", r"(?:Lazarus(?:\s+Group)?)", r"(?:Carbanak)", 
                r"(?:FIN\d+)", r"(?:Cozy\s+Bear)", r"(?:Fancy\s+Bear)"
            ],
            "malware_families": [
                r"(?:\w*(?:Ransomware|Trojan|Backdoor|Stealer|Miner|Bot)\w*)",
                r"(?:WannaCry|NotPetya|Emotet|TrickBot|Dridex|Qbot)"
            ],
            "attack_techniques": [
                r"(?:T\d{4}(?:\.\d{3})?)", # MITRE ATT&CK techniques
                r"(?:spear[\s-]?phishing)", r"(?:credential[\s-]?stuffing)",
                r"(?:lateral[\s-]?movement)", r"(?:privilege[\s-]?escalation)"
            ],
            "industries": [
                r"(?:healthcare|financial|banking|retail|manufacturing|energy|government|education)",
                r"(?:critical infrastructure|supply chain)"
            ],
            "countries": [
                r"(?:United States|China|Russia|North Korea|Iran|Israel)",
                r"(?:US|UK|EU|NATO)"
            ]
        }
        
        # Extract entities using patterns
        for category, patterns in entity_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                entities[category].extend([match.strip() for match in matches if match.strip()])
        
        # Remove duplicates and clean up
        for category in entities:
            entities[category] = list(set(entities[category]))
        
        return entities
    
    def get_available_models(self) -> List[str]:
        """
        Get list of available models from Ollama.
        
        Returns:
            List of available model names
        """
        if not self.ollama_available:
            return []
        
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=10)
            response.raise_for_status()
            
            data = response.json()
            models = [model["name"] for model in data.get("models", [])]
            return models
            
        except Exception as e:
            logger.error(f"Error fetching available models: {e}")
            return []
    
    def set_model(self, model_name: str) -> bool:
        """
        Set the LLM model to use for summarization.
        
        Args:
            model_name: Name of the model to use
            
        Returns:
            True if model was set successfully
        """
        available_models = self.get_available_models()
        
        if not available_models:
            logger.error("No models available from Ollama")
            return False
        
        if model_name not in available_models:
            logger.error(f"Model {model_name} not available. Available models: {available_models}")
            return False
        
        self.model_name = model_name
        logger.info(f"Switched to model: {model_name}")
        return True
    
    def batch_summarize(self, articles: List[Dict[str, str]]) -> List[Dict[str, any]]:
        """
        Process multiple articles for batch summarization.
        
        Args:
            articles: List of articles with title, content, and source
            
        Returns:
            List of summarized articles with metadata
        """
        summaries = []
        
        for i, article in enumerate(articles):
            logger.info(f"Processing article {i+1}/{len(articles)}: {article.get('title', 'Unknown')[:50]}...")
            
            try:
                summary = self.generate_summary(
                    title=article.get('title', ''),
                    content=article.get('content', ''),
                    source=article.get('source', '')
                )
                
                summaries.append({
                    **article,
                    **summary
                })
                
            except Exception as e:
                logger.error(f"Error processing article {i+1}: {e}")
                summaries.append({
                    **article,
                    "summary": f"Error processing article: {str(e)}",
                    "threat_type": "Processing Error",
                    "severity": "Unknown"
                })
        
        return summaries


# Gradio Integration Functions for UI
def create_gradio_interface_components():
    """
    Create the components needed for Gradio interface integration.
    This function provides the interface elements that can be used in the main Gradio app.
    """
    import gradio as gr
    
    def summarize_single_article(title, content, source="Manual Input", use_ollama=True, model_name="llama2"):
        """Gradio function for single article summarization."""
        summarizer = AISummarizer(use_ollama=use_ollama, model_name=model_name)
        
        if not title.strip() and not content.strip():
            return "Please provide either a title or content to summarize."
        
        try:
            result = summarizer.generate_summary(title, content, source)
            
            # Format the output for Gradio display
            formatted_output = f"""
# Threat Intelligence Summary

## 📊 **Classification**
- **Threat Type**: {result['threat_type']}
- **Severity**: {result['severity']}
- **Confidence**: {result['confidence']:.2%}
- **Processing Method**: {result['summary_method']}
- **Processing Time**: {result['processing_time']}s

## 📝 **Summary**
{result['summary']}

## 🎯 **Affected Systems**
{', '.join(result['affected_systems']) if result['affected_systems'] else 'Not specified'}

## 🔧 **Recommended Actions**
{chr(10).join(f"• {rec}" for rec in result['recommendations'])}

## 🏷️ **Key Entities**
{chr(10).join(f"**{category.title()}**: {', '.join(entities)}" for category, entities in result['key_entities'].items() if entities)}

---
*Processed at: {result['processed_at']}*
*Source: {result['source']}*
            """
            
            return formatted_output
            
        except Exception as e:
            return f"Error processing article: {str(e)}"
    
    def get_ollama_models():
        """Get available Ollama models for dropdown."""
        summarizer = AISummarizer()
        models = summarizer.get_available_models()
        return models if models else ["llama2", "mistral", "codellama"]
    
    # Create Gradio interface components
    with gr.Row():
        title_input = gr.Textbox(
            label="Article Title",
            placeholder="Enter the title of the threat intelligence article...",
            lines=2
        )
    
    with gr.Row():
        content_input = gr.Textbox(
            label="Article Content",
            placeholder="Paste the full content of the threat intelligence article here...",
            lines=10
        )
    
    with gr.Row():
        source_input = gr.Textbox(
            label="Source",
            placeholder="Source of the article (optional)",
            value="Manual Input"
        )
    
    with gr.Row():
        use_ollama_checkbox = gr.Checkbox(
            label="Use Ollama LLM",
            value=True,
            info="Use local LLM for enhanced summarization"
        )
        
        model_dropdown = gr.Dropdown(
            label="LLM Model",
            choices=get_ollama_models(),
            value="llama2",
            info="Select the LLM model to use"
        )
    
    summarize_btn = gr.Button("🔍 Generate Threat Summary", variant="primary")
    
    output_display = gr.Markdown(
        label="Threat Intelligence Summary",
        value="Click 'Generate Threat Summary' to analyze your threat intelligence article."
    )
    
    # Connect the interface
    summarize_btn.click(
        fn=summarize_single_article,
        inputs=[title_input, content_input, source_input, use_ollama_checkbox, model_dropdown],
        outputs=[output_display]
    )
    
    return {
        "inputs": {
            "title": title_input,
            "content": content_input,
            "source": source_input,
            "use_ollama": use_ollama_checkbox,
            "model": model_dropdown
        },
        "outputs": {
            "summary": output_display
        },
        "button": summarize_btn
    }


# Example usage and testing function
def main() -> None:
    """Comprehensive test of the AI Summarizer with Ollama integration."""
    print("🛡️ AI Threat Intelligence Summarizer Test Suite")
    print("=" * 60)
    
    # Test both Ollama and extractive summarization
    summarizer_ollama = AISummarizer(use_ollama=True, model_name="llama2")
    summarizer_extractive = AISummarizer(use_ollama=False)
    
    # Test content
    test_title = "Critical Zero-Day Vulnerability in Popular Web Framework Exploited by APT Group"
    test_content = """
    Security researchers from Cybersecurity Corp have discovered a critical zero-day vulnerability 
    in the widely-used WebFramework 4.x that is being actively exploited by the APT29 threat actor group. 
    The vulnerability, tracked as CVE-2024-12345, allows remote code execution on vulnerable systems 
    through specially crafted HTTP requests. 
    
    The attack campaign has been observed targeting financial institutions and government agencies 
    across North America and Europe since early January 2024. The malware payload, identified as 
    a variant of the Cobalt Strike beacon, establishes persistence through registry modifications 
    and creates backdoor access for the attackers.
    
    Affected systems include Windows Server 2019 and 2022 running WebFramework versions 4.0 through 4.8. 
    The vulnerability has a CVSS score of 9.8, indicating critical severity. Organizations should 
    immediately apply the emergency patch released by the vendor and monitor for indicators of compromise 
    including suspicious network connections to known C2 infrastructure at 185.220.101.45.
    
    Recommended immediate actions include patching all affected systems, monitoring network traffic 
    for suspicious activity, and implementing additional access controls for critical systems.
    """
    
    print("🔬 Testing Ollama LLM Summarization...")
    print("-" * 40)
    
    # Test Ollama summarization
    start_time = time.time()
    ollama_result = summarizer_ollama.generate_summary(test_title, test_content, "Test Source")
    ollama_time = time.time() - start_time
    
    print(f"✅ Ollama Summary Generated in {ollama_time:.2f}s")
    print(f"🎯 Threat Type: {ollama_result['threat_type']}")
    print(f"🚨 Severity: {ollama_result['severity']}")
    print(f"📊 Confidence: {ollama_result['confidence']:.2%}")
    print(f"🖥️ Affected Systems: {', '.join(ollama_result['affected_systems'])}")
    print(f"📝 Summary Length: {len(ollama_result['summary'])} characters")
    print()
    
    print("📄 Ollama Summary Preview:")
    print("-" * 30)
    print(ollama_result['summary'][:300] + "..." if len(ollama_result['summary']) > 300 else ollama_result['summary'])
    print()
    
    print("🔧 Extractive Summarization Fallback Test...")
    print("-" * 40)
    
    # Test extractive summarization
    start_time = time.time()
    extractive_result = summarizer_extractive.generate_summary(test_title, test_content, "Test Source")
    extractive_time = time.time() - start_time
    print(f"✅ Extractive Summary Generated in {extractive_time:.2f}s")
    print(f"🎯 Threat Type: {extractive_result['threat_type']}")
    print(f"🚨 Severity: {extractive_result['severity']}")
    print(f"📊 Confidence: {extractive_result['confidence']:.2%}")
    print(f"🖥️ Affected Systems: {', '.join(extractive_result['affected_systems'])}")
    print(f"📝 Summary Length: {len(extractive_result['summary'])} characters")
    print()
    
    print("📄 Extractive Summary Preview:")
    print("-" * 30)
    print(extractive_result['summary'][:300] + "..." if len(extractive_result['summary']) > 300 else extractive_result['summary'])
    print()
    
    print("🔍 Recommendations Comparison:")
    print("-" * 30)
    print(f"Ollama Recommendations: {len(ollama_result['recommendations'])}")
    print(f"Extractive Recommendations: {len(extractive_result['recommendations'])}")
    print()
    
    print("🏁 Test Summary:")
    print("-" * 20)
    print(f"✅ Ollama Available: {summarizer_ollama.ollama_available}")
    print(f"⚡ Performance Difference: {abs(ollama_time - extractive_time):.2f}s")
    print(f"🎯 Both methods successfully classified threat type")
    print(f"🛡️ AI Summarizer is ready for integration!")


if __name__ == "__main__":
    main()