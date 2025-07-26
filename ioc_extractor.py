import re
import ipaddress
import logging
from typing import Dict, List, Set, Optional, Union, Tuple, Any
from urllib.parse import urlparse
from dataclasses import dataclass, field
from collections import defaultdict
import json
from datetime import datetime
import time
# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import validators, with fallback
try:
    import validators
    HAS_VALIDATORS = True
except ImportError:
    logger.warning("validators library not available. Using built-in URL validation.")
    HAS_VALIDATORS = False

@dataclass
class IOCResult:
    """Enhanced data class to structure IOC extraction results for threat intelligence feeds."""
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    executable_files: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    bitcoin_addresses: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    mutex_names: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    yara_rules: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    asn_numbers: List[str] = field(default_factory=list)
    
    # Metadata for threat intelligence analysis
    extraction_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary format for compatibility with existing systems."""
        return {
            'ip_addresses': self.ip_addresses,
            'domains': self.domains,
            'urls': self.urls,
            'hashes': self.hashes,
            'emails': self.emails,
            'executable_files': self.executable_files,
            'cve_ids': self.cve_ids,
            'bitcoin_addresses': self.bitcoin_addresses,
            'registry_keys': self.registry_keys,
            'file_paths': self.file_paths,
            'ports': self.ports,
            'mutex_names': self.mutex_names,
            'user_agents': self.user_agents,
            'mac_addresses': self.mac_addresses,
            'yara_rules': self.yara_rules,
            'mitre_techniques': self.mitre_techniques,
            'asn_numbers': self.asn_numbers
        }
    
    def to_json(self) -> str:
        """Convert to JSON string for file storage."""
        data = self.to_dict()
        data['extraction_metadata'] = self.extraction_metadata
        return json.dumps(data, indent=2, default=str)
    
    def get_total_count(self) -> int:
        """Get total number of IOCs found."""
        return sum(len(ioc_list) for ioc_list in self.to_dict().values())
    
    def get_high_confidence_iocs(self) -> Dict[str, List[str]]:
        """Get IOCs that have high confidence scores."""
        high_confidence = {}
        confidence_data = self.extraction_metadata.get('confidence_scores', {})
        
        for ioc_type, iocs in self.to_dict().items():
            if ioc_type in confidence_data and confidence_data[ioc_type] >= 0.7:
                high_confidence[ioc_type] = iocs
        
        return high_confidence

class ThreatIntelligenceIOCExtractor:
    """
    Enhanced IOC extractor specifically designed for threat intelligence feed aggregation.
    Optimized for processing RSS/Atom feeds, GitHub threat intel repositories, and security blogs.
    Follows modular architecture as per technical requirements.
    """
    
    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None, 
                 confidence_threshold: float = 0.5) -> None:
        """
        Initialize the threat intelligence IOC extractor.
        
        Args:
            custom_patterns: Dictionary of custom regex patterns {name: pattern}
            confidence_threshold: Minimum confidence score for IOC inclusion
        """
        self.custom_patterns = custom_patterns or {}
        self.confidence_threshold = confidence_threshold
        
        # Initialize components following modular architecture
        self._compile_patterns()
        self._initialize_threat_intel_filters()
        self._initialize_context_analysis()
        self._initialize_confidence_scoring()
        
        logger.info("Threat Intelligence IOC Extractor initialized successfully")
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns optimized for threat intelligence content."""
        self.compiled_patterns = {
            # Enhanced IP address pattern with CIDR support
            'ip_addresses': re.compile(
                r'(?<![\d.])\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:/(?:3[0-2]|[12]?[0-9]))?\b(?![\d.])'
            ),
            
            # Domain pattern with threat intelligence focus
            'domains': re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b'
            ),
            
            # Comprehensive URL pattern for malicious URLs
            'urls': re.compile(
                r'(?:(?:https?|ftp|sftp)://)'
                r'(?:[a-zA-Z0-9\-._~!$&\'()*+,;=]|%[0-9a-fA-F]{2})*'
                r'@?'
                r'(?:[a-zA-Z0-9\-._~!$&\'()*+,;=]|%[0-9a-fA-F]{2})*'
                r'(?::[0-9]*)?'
                r'(?:/(?:[a-zA-Z0-9\-._~!$&\'()*+,;=:@]|%[0-9a-fA-F]{2})*)*'
                r'(?:\?(?:[a-zA-Z0-9\-._~!$&\'()*+,;=:@/?]|%[0-9a-fA-F]{2})*)?'
                r'(?:#(?:[a-zA-Z0-9\-._~!$&\'()*+,;=:@/?]|%[0-9a-fA-F]{2})*)?',
                re.IGNORECASE
            ),
            
            # Hash patterns with enhanced validation
            'md5_hashes': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1_hashes': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256_hashes': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'sha512_hashes': re.compile(r'\b[a-fA-F0-9]{128}\b'),
            'ntlm_hashes': re.compile(r'\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b'),
            'ssdeep_hashes': re.compile(r'\b\d+:[a-zA-Z0-9/+]{3,}:[a-zA-Z0-9/+]{3,}\b'),
            
            # Email pattern with threat actor focus
            'emails': re.compile(
                r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
            ),
            
            # Executable files with enhanced extensions
            'executable_files': re.compile(
                r'\b\w+\.(?:exe|dll|bat|cmd|ps1|vbs|js|jse|hta|scr|com|pif|msi|jar|app|dmg|pkg|deb|rpm|apk|ipa|elf|bin|so|dylib)\b',
                re.IGNORECASE
            ),
            
            # CVE pattern with flexible formatting
            'cve_ids': re.compile(r'CVE[-\s]?\d{4}[-\s]?\d{4,7}', re.IGNORECASE),
            
            # Cryptocurrency addresses (multiple currencies)
            'bitcoin_addresses': re.compile(
                r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b'
            ),
            'ethereum_addresses': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            'monero_addresses': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
            
            # Windows registry keys
            'registry_keys': re.compile(
                r'(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CURRENT_CONFIG|CLASSES_ROOT|PERFORMANCE_DATA|DYN_DATA)'
                r'|HKLM|HKCU|HKU|HKCC|HKCR)'
                r'\\[^\s\r\n<>"|*?]+',
                re.IGNORECASE
            ),
            
            # File paths (Windows and Unix)
            'file_paths': re.compile(
                r'(?:[a-zA-Z]:\\(?:[^\s<>:"|*?\r\n\\]+\\)*[^\s<>:"|*?\r\n\\]*'
                r'|/(?:[^\s<>\r\n/]+/)*[^\s<>\r\n/]*)',
                re.IGNORECASE
            ),
            
            # Network ports with context
            'ports': re.compile(r'(?:port\s+|:|tcp/|udp/)(\d{1,5})\b', re.IGNORECASE),
            
            # Mutex names
            'mutex_names': re.compile(
                r'(?:mutex|mutant)[\s:]+([a-zA-Z0-9_\-\\{}]+)',
                re.IGNORECASE
            ),
            
            # User-Agent strings
            'user_agents': re.compile(
                r'User-Agent:\s*([^\r\n]+)',
                re.IGNORECASE
            ),
            
            # MAC addresses
            'mac_addresses': re.compile(
                r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
            ),
            
            # YARA rule names
            'yara_rules': re.compile(
                r'rule\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                re.IGNORECASE
            ),
            
            # ASN numbers
            'asn_numbers': re.compile(r'\bAS(\d{1,6})\b', re.IGNORECASE),
            
            # MITRE ATT&CK techniques
            'mitre_techniques': re.compile(r'\bT\d{4}(?:\.\d{3})?\b'),
            
            # Threat actor names and campaigns
            'threat_actors': re.compile(
                r'\b(?:APT[\s-]?\d+|Lazarus|Carbanak|FIN\d+|Cozy\s+Bear|Fancy\s+Bear|Equation\s+Group)\b',
                re.IGNORECASE
            ),
            
            # Malware families
            'malware_families': re.compile(
                r'\b(?:Emotet|TrickBot|Dridex|Qbot|WannaCry|NotPetya|Stuxnet|Zeus|Conficker)\b',
                re.IGNORECASE
            ),
        }
        
        # Add custom patterns from threat intelligence sources
        for name, pattern in self.custom_patterns.items():
            try:
                self.compiled_patterns[f'custom_{name}'] = re.compile(pattern, re.IGNORECASE)
                logger.info(f"Added custom pattern: {name}")
            except re.error as e:
                logger.warning(f"Invalid custom pattern '{name}': {e}")
    
    def _initialize_threat_intel_filters(self) -> None:
        """Initialize filters specific to threat intelligence feeds."""
        # Known threat intelligence domains (should not be filtered)
        self.threat_intel_sources: Set[str] = {
            'virustotal.com', 'hybrid-analysis.com', 'any.run', 'joesandbox.com',
            'malwarebytes.com', 'fireeye.com', 'crowdstrike.com', 'mandiant.com',
            'krebsonsecurity.com', 'bleepingcomputer.com', 'threatpost.com',
            'darkreading.com', 'securityweek.com', 'thehackernews.com'
        }
        
        # Legitimate domains to filter out (unless in threat context)
        self.legitimate_domains: Set[str] = {
            'google.com', 'microsoft.com', 'amazon.com', 'facebook.com',
            'apple.com', 'github.com', 'youtube.com', 'twitter.com',
            'linkedin.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org',
            'cloudflare.com', 'amazonaws.com', 'azure.com', 'office.com'
        }
        
        # Common malware file extensions (higher confidence)
        self.malware_extensions: Set[str] = {
            'exe', 'scr', 'pif', 'com', 'bat', 'cmd', 'vbs', 'js', 'jar',
            'dll', 'sys', 'hta', 'msi', 'ps1', 'wsf', 'lnk'
        }
        
        # Suspicious TLDs commonly used by threat actors
        self.suspicious_tlds: Set[str] = {
            'tk', 'ml', 'ga', 'cf', 'pw', 'top', 'click', 'download',
            'work', 'date', 'review', 'country', 'stream', 'accountant'
        }
        
        # Reserved/example IP ranges to filter
        self.reserved_ip_ranges = [
            ipaddress.ip_network('192.0.2.0/24'), # TEST-NET-1
            ipaddress.ip_network('198.51.100.0/24'), # TEST-NET-2
            ipaddress.ip_network('203.0.113.0/24'), # TEST-NET-3
            ipaddress.ip_network('192.168.0.0/16'), # Private
            ipaddress.ip_network('10.0.0.0/8'), # Private
            ipaddress.ip_network('172.16.0.0/12'), # Private
            ipaddress.ip_network('127.0.0.0/8'), # Loopback
            ipaddress.ip_network('169.254.0.0/16'), # Link-local
        ]
    
    def _initialize_context_analysis(self) -> None:
        """Initialize context analysis for better IOC classification."""
        # Threat context keywords (increase confidence)
        self.threat_context_keywords = [
            'malicious', 'suspicious', 'infected', 'compromised', 'backdoor',
            'trojan', 'ransomware', 'malware', 'c2', 'command.{0,10}control',
            'botnet', 'payload', 'exploit', 'vulnerability', 'attack',
            'campaign', 'threat actor', 'indicator', 'ioc', 'compromise'
        ]
        
        # Benign context keywords (decrease confidence)
        self.benign_context_keywords = [
            'example', 'sample', 'test', 'documentation', 'tutorial',
            'legitimate', 'whitelist', 'allow', 'safe', 'clean',
            'false positive', 'benign', 'normal', 'expected'
        ]
        
        # Compile context patterns
        self.threat_context_pattern = re.compile(
            '|'.join(self.threat_context_keywords), re.IGNORECASE
        )
        
        self.benign_context_pattern = re.compile(
            '|'.join(self.benign_context_keywords), re.IGNORECASE
        )
    
    def _initialize_confidence_scoring(self) -> None:
        """Initialize confidence scoring system for IOCs."""
        # Base confidence scores by IOC type
        self.base_confidence_scores = {
            'hashes': 0.9, # Hashes are usually high confidence
            'cve_ids': 0.95, # CVEs are very specific
            'bitcoin_addresses': 0.9, # Crypto addresses are high confidence
            'ethereum_addresses': 0.9,
            'monero_addresses': 0.9,
            'yara_rules': 0.85, # YARA rules are specific
            'mitre_techniques': 0.9, # MITRE techniques are reliable
            'registry_keys': 0.8, # Registry keys are good indicators
            'mutex_names': 0.8, # Mutex names are reliable
            'executable_files': 0.7, # Executables need context
            'urls': 0.75, # URLs are usually good
            'ip_addresses': 0.6, # IPs need more validation
            'domains': 0.5, # Domains can be noisy
            'emails': 0.4, # Emails are often false positives
            'ports': 0.3, # Ports are very common
            'file_paths': 0.6, # File paths are moderate confidence
            'user_agents': 0.7, # User agents are good indicators
            'mac_addresses': 0.6, # MAC addresses are moderate
            'asn_numbers': 0.7, # ASN numbers are good indicators
        }
    def extract_iocs(self, content: str) -> IOCResult:
        """Wrapper method for backward compatibility."""
        result = self.extract_iocs_from_feed_content(content)
        return result

    def extract_iocs_from_feed_content(self, content: str, source_url: str = "", 
                                     feed_type: str = "rss") -> IOCResult:
        """
        Main extraction method optimized for threat intelligence feeds.
        
        Args:
            content: Raw content from RSS/Atom feed or threat intel source
            source_url: URL of the source feed
            feed_type: Type of feed (rss, atom, github, blog)
            
        Returns:
            IOCResult object containing all extracted IOCs with metadata
        """
        if not isinstance(content, str) or not content.strip():
            return IOCResult()
        
        start_time = time.time()
        
        # Preprocess content for better extraction
        processed_content = self._preprocess_threat_content(content)
        
        # Initialize result object
        result = IOCResult()
        
        # Extract all IOC types
        result.ip_addresses = self._extract_and_validate_ips(processed_content)
        result.domains = self._extract_and_validate_domains(processed_content)
        result.urls = self._extract_and_validate_urls(processed_content)
        result.hashes = self._extract_and_validate_hashes(processed_content)
        result.emails = self._extract_threat_emails(processed_content)
        result.executable_files = self._extract_executable_files(processed_content)
        result.cve_ids = self._extract_cve_identifiers(processed_content)
        result.bitcoin_addresses = self._extract_crypto_addresses(processed_content, 'bitcoin')
        result.registry_keys = self._extract_registry_keys(processed_content)
        result.file_paths = self._extract_file_paths(processed_content)
        result.ports = self._extract_network_ports(processed_content)
        result.mutex_names = self._extract_mutex_names(processed_content)
        result.user_agents = self._extract_user_agents(processed_content)
        result.mac_addresses = self._extract_mac_addresses(processed_content)
        result.yara_rules = self._extract_yara_rules(processed_content)
        result.mitre_techniques = self._extract_mitre_techniques(processed_content)
        result.asn_numbers = self._extract_asn_numbers(processed_content)
        
        # Calculate confidence scores
        confidence_scores = self._calculate_confidence_scores(processed_content, result)
        
        # Store extraction metadata
        processing_time = time.time() - start_time
        result.extraction_metadata = {
            'source_url': source_url,
            'feed_type': feed_type,
            'processing_time': processing_time,
            'extracted_at': datetime.now().isoformat(),
            'confidence_scores': confidence_scores,
            'total_iocs': result.get_total_count(),
            'content_length': len(content),
            'threat_context_detected': self._detect_threat_context(processed_content)
        }
        
        # Filter by confidence threshold
        if self.confidence_threshold > 0:
            result = self._filter_by_confidence(result, confidence_scores)
        
        logger.info(f"Extracted {result.get_total_count()} IOCs in {processing_time:.3f}s from {feed_type} feed")
        
        return result
    
    def _preprocess_threat_content(self, content: str) -> str:
        """Preprocess content with threat intelligence specific cleaning."""
        # Common defanging patterns used in threat reports
        content = content.replace('[.]', '.')
        content = content.replace('(.)', '.')
        content = content.replace('[:]', ':')
        content = content.replace('(:)', ':')
        content = content.replace('[@]', '@')
        content = content.replace('(@)', '@')
        
        # URL defanging
        content = content.replace('hxxp', 'http')
        content = content.replace('hXXp', 'http')
        content = content.replace('h**p', 'http')
        content = content.replace('h[tt]p', 'http')
        
        # IP defanging
        content = re.sub(r'(\d+)\[?\.\]?(\d+)\[?\.\]?(\d+)\[?\.\]?(\d+)', r'\1.\2.\3.\4', content)
        
        # Domain defanging
        content = re.sub(r'([a-zA-Z0-9-]+)\[?\.\]?([a-zA-Z]{2,})', r'\1.\2', content)
        
        # Clean up excessive whitespace while preserving structure
        content = re.sub(r'\s+', ' ', content)
        content = re.sub(r'\n\s*\n', '\n\n', content)
        
        return content
    
    def _extract_and_validate_ips(self, content: str) -> List[str]:
        """Extract and validate IP addresses with threat intelligence focus."""
        ip_matches = self.compiled_patterns['ip_addresses'].findall(content)
        valid_ips = []
        
        for ip_str in ip_matches:
            # Handle CIDR notation
            if '/' in ip_str:
                ip_part = ip_str.split('/')[0]
                cidr_part = ip_str.split('/')[1]
            else:
                ip_part = ip_str
                cidr_part = None
            
            try:
                ip_obj = ipaddress.ip_address(ip_part)
                
                # Skip private, loopback, multicast, and reserved IPs
                if not (ip_obj.is_private or ip_obj.is_loopback or 
                       ip_obj.is_multicast or ip_obj.is_reserved):
                    
                    # Check against reserved ranges
                    if not self._is_reserved_ip(ip_obj):
                        # Check for threat context
                        if self._has_threat_context(content, ip_str):
                            valid_ips.append(ip_str)
                        elif not self._has_benign_context(content, ip_str):
                            valid_ips.append(ip_str)
                            
            except ValueError:
                continue
        
        return list(set(valid_ips))
    
    def _extract_and_validate_domains(self, content: str) -> List[str]:
        """Extract and validate domains with threat intelligence filtering."""
        domain_matches = self.compiled_patterns['domains'].findall(content)
        valid_domains = []
        
        for domain in domain_matches:
            domain_lower = domain.lower().strip()
            
            # Basic validation
            if not self._is_valid_domain_format(domain_lower):
                continue
            
            # Skip legitimate domains unless in threat context
            is_legitimate = any(legit in domain_lower for legit in self.legitimate_domains)
            is_threat_intel_source = any(source in domain_lower for source in self.threat_intel_sources)
            
            if is_threat_intel_source:
                continue # Skip threat intel source domains
            
            if is_legitimate and not self._has_threat_context(content, domain):
                continue
            
            # Check for suspicious TLD
            tld = domain_lower.split('.')[-1]
            has_suspicious_tld = tld in self.suspicious_tlds
            
            # Include if suspicious TLD or has threat context
            if has_suspicious_tld or self._has_threat_context(content, domain):
                valid_domains.append(domain_lower)
            elif not self._has_benign_context(content, domain):
                valid_domains.append(domain_lower)
        
        return list(set(valid_domains))
    
    def _extract_and_validate_urls(self, content: str) -> List[str]:
        """Extract and validate URLs with malicious indicators."""
        url_matches = self.compiled_patterns['urls'].findall(content)
        valid_urls = []
        
        for url in url_matches:
            url = url.strip()
            
            if not self._is_valid_url_format(url):
                continue
            
            # Check for malicious indicators
            if self._has_malicious_url_indicators(url):
                valid_urls.append(url)
            elif self._has_threat_context(content, url):
                valid_urls.append(url)
            elif not self._is_legitimate_url(url) and not self._has_benign_context(content, url):
                valid_urls.append(url)
        
        return list(set(valid_urls))
    
    def _extract_and_validate_hashes(self, content: str) -> List[str]:
        """Extract file hashes with comprehensive validation."""
        all_hashes = []
        
        hash_types = ['md5_hashes', 'sha1_hashes', 'sha256_hashes', 'sha512_hashes', 
                     'ntlm_hashes', 'ssdeep_hashes']
        
        for hash_type in hash_types:
            if hash_type in self.compiled_patterns:
                hashes = self.compiled_patterns[hash_type].findall(content)
                
                for hash_val in hashes:
                    if self._is_valid_hash_format(hash_val, hash_type):
                        all_hashes.append(hash_val.lower())
        
        return list(set(all_hashes))
    
    def _extract_threat_emails(self, content: str) -> List[str]:
        """Extract email addresses relevant to threat intelligence."""
        email_matches = self.compiled_patterns['emails'].findall(content)
        threat_emails = []
        
        for email in email_matches:
            email_lower = email.lower().strip()
            domain = email_lower.split('@')[1] if '@' in email_lower else ''
            
            # Skip common legitimate email domains unless in threat context
            if domain in {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'}:
                if not self._has_threat_context(content, email):
                    continue
            
            # Include if has threat context or from suspicious domain
            if (self._has_threat_context(content, email) or 
                self._is_suspicious_email_domain(domain)):
                threat_emails.append(email_lower)
        
        return list(set(threat_emails))
    
    def _extract_executable_files(self, content: str) -> List[str]:
        """Extract executable file names with malware focus."""
        file_matches = self.compiled_patterns['executable_files'].findall(content)
        executable_files = []
        
        for filename in file_matches:
            filename_lower = filename.lower()
            
            # Skip generic filenames
            if self._is_generic_filename(filename_lower):
                continue
            
            # Higher confidence for known malware extensions
            extension = filename_lower.split('.')[-1] if '.' in filename_lower else ''
            if extension in self.malware_extensions:
                executable_files.append(filename_lower)
            elif self._has_threat_context(content, filename):
                executable_files.append(filename_lower)
        
        return list(set(executable_files))
    
    def _extract_cve_identifiers(self, content: str) -> List[str]:
        """Extract CVE identifiers with normalization."""
        cve_matches = self.compiled_patterns['cve_ids'].findall(content)
        normalized_cves = []
        
        for cve in cve_matches:
            # Normalize CVE format to standard CVE-YYYY-NNNNN
            normalized = re.sub(r'CVE[-\s]?(\d{4})[-\s]?(\d{4,7})', 
                              r'CVE-\1-\2', cve.upper())
            
            # Validate CVE format
            if re.match(r'CVE-\d{4}-\d{4,7}', normalized):
                normalized_cves.append(normalized)
        
        return list(set(normalized_cves))
    
    def _extract_crypto_addresses(self, content: str, crypto_type: str) -> List[str]:
        """Extract cryptocurrency addresses."""
        if crypto_type == 'bitcoin':
            pattern_key = 'bitcoin_addresses'
        elif crypto_type == 'ethereum':
            pattern_key = 'ethereum_addresses'
        elif crypto_type == 'monero':
            pattern_key = 'monero_addresses'
        else:
            return []
        
        if pattern_key in self.compiled_patterns:
            matches = self.compiled_patterns[pattern_key].findall(content)
            return list(set(matches))
        
        return []
    
    def _extract_registry_keys(self, content: str) -> List[str]:
        """Extract Windows registry keys."""
        reg_matches = self.compiled_patterns['registry_keys'].findall(content)
        valid_keys = []
        
        for reg_key in reg_matches:
            # Filter out very generic registry paths
            if not self._is_generic_registry_key(reg_key):
                valid_keys.append(reg_key)
        
        return list(set(valid_keys))
    
    def _extract_file_paths(self, content: str) -> List[str]:
        """Extract file paths with validation."""
        path_matches = self.compiled_patterns['file_paths'].findall(content)
        valid_paths = []
        
        for path in path_matches:
            # Filter out very generic or short paths
            if len(path) > 5 and not self._is_generic_path(path):
                valid_paths.append(path)
        
        return list(set(valid_paths))
    
    def _extract_network_ports(self, content: str) -> List[str]:
        """Extract network ports with validation."""
        port_matches = self.compiled_patterns['ports'].findall(content)
        valid_ports = []
        
        for port in port_matches:
            try:
                port_num = int(port)
                # Valid port range and not too common
                if 1 <= port_num <= 65535 and not self._is_common_port(port_num):
                    valid_ports.append(port)
            except ValueError:
                continue
        
        return list(set(valid_ports))
    
    def _extract_mutex_names(self, content: str) -> List[str]:
        """Extract mutex names."""
        mutex_matches = self.compiled_patterns['mutex_names'].findall(content)
        return list(set(mutex_matches))
    
    def _extract_user_agents(self, content: str) -> List[str]:
        """Extract User-Agent strings."""
        ua_matches = self.compiled_patterns['user_agents'].findall(content)
        valid_uas = []
        
        for ua in ua_matches:
            # Filter out common legitimate user agents
            if not self._is_common_user_agent(ua):
                valid_uas.append(ua.strip())
        
        return list(set(valid_uas))
    
    def _extract_mac_addresses(self, content: str) -> List[str]:
        """Extract MAC addresses."""
        mac_matches = self.compiled_patterns['mac_addresses'].findall(content)
        return list(set(mac_matches))
    
    def _extract_yara_rules(self, content: str) -> List[str]:
        """Extract YARA rule names."""
        yara_matches = self.compiled_patterns['yara_rules'].findall(content)
        return list(set(yara_matches))
    
    def _extract_mitre_techniques(self, content: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs."""
        mitre_matches = self.compiled_patterns['mitre_techniques'].findall(content)
        return list(set(mitre_matches))
    
    def _extract_asn_numbers(self, content: str) -> List[str]:
        """Extract ASN numbers."""
        asn_matches = self.compiled_patterns['asn_numbers'].findall(content)
        return list(set(asn_matches))
    
    # Helper methods for validation and filtering
    
    def _is_reserved_ip(self, ip_obj: ipaddress.IPv4Address) -> bool:
        """Check if IP is in reserved ranges."""
        for network in self.reserved_ip_ranges:
            if ip_obj in network:
                return True
        return False
    
    def _is_valid_domain_format(self, domain: str) -> bool:
        """Validate domain format and structure."""
        if not domain or len(domain) < 4:
            return False
        
        # Check for valid TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        tld = parts[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False
        
        # Check for version numbers or IP-like patterns
        if re.match(r'^\d+\.\d+', domain):
            return False
        
        return True
    
    def _is_valid_url_format(self, url: str) -> bool:
        """Validate URL format."""
        if HAS_VALIDATORS:
            try:
                return validators.url(url)
            except:
                return False
        else:
            try:
                parsed = urlparse(url)
                return parsed.scheme in ('http', 'https', 'ftp') and parsed.netloc
            except:
                return False
    
    def _has_malicious_url_indicators(self, url: str) -> bool:
        """Check if URL has malicious indicators."""
        suspicious_indicators = [
            'download', 'payload', 'malware', 'exploit', 'shell',
            'backdoor', 'trojan', 'virus', 'keylog', 'stealer',
            'ransomware', 'botnet', 'c2', 'cmd', 'evil'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in suspicious_indicators)
    
    def _is_legitimate_url(self, url: str) -> bool:
        """Check if URL belongs to legitimate services."""
        try:
            domain = urlparse(url).netloc.lower()
            return any(legit in domain for legit in self.legitimate_domains)
        except:
            return False
    
    def _is_valid_hash_format(self, hash_val: str, hash_type: str) -> bool:
        """Validate hash format and characteristics."""
        # Check for obvious patterns that aren't real hashes
        if hash_val == '0' * len(hash_val): # All zeros
            return False
        if hash_val == 'a' * len(hash_val): # All same character
            return False
        
        # Check expected lengths
        expected_lengths = {
            'md5_hashes': 32,
            'sha1_hashes': 40,
            'sha256_hashes': 64,
            'sha512_hashes': 128
        }
        
        if hash_type in expected_lengths:
            return len(hash_val) == expected_lengths[hash_type]
        
        return True
    
    def _is_suspicious_email_domain(self, domain: str) -> bool:
        """Check if email domain is suspicious."""
        tld = domain.split('.')[-1] if '.' in domain else domain
        return tld in self.suspicious_tlds
    
    def _is_generic_filename(self, filename: str) -> bool:
        """Check if filename is too generic."""
        generic_names = {
            'file.exe', 'program.exe', 'setup.exe', 'install.exe',
            'update.exe', 'test.exe', 'sample.exe', 'example.exe',
            'app.exe', 'tool.exe', 'utility.exe', 'main.exe'
        }
        return filename in generic_names
    
    def _is_generic_registry_key(self, reg_key: str) -> bool:
        """Check if registry key is too generic."""
        generic_patterns = [
            r'HKLM\\SOFTWARE',
            r'HKCU\\SOFTWARE',
            r'HKEY_LOCAL_MACHINE\\SOFTWARE',
            r'HKEY_CURRENT_USER\\SOFTWARE'
        ]
        
        for pattern in generic_patterns:
            if re.match(pattern, reg_key, re.IGNORECASE):
                return True
        
        return False
    
    def _is_generic_path(self, path: str) -> bool:
        """Check if path is too generic."""
        generic_indicators = [
            'c:', 'd:', '/usr', '/var', '/tmp', '/home',
            'c:\\windows', 'c:\\program files'
        ]
        path_lower = path.lower()
        
        # Check if path is just a drive letter or very basic system path
        for indicator in generic_indicators:
            if path_lower.startswith(indicator) and len(path) < 15:
                return True
        
        return False
    
    def _is_common_port(self, port: int) -> bool:
        """Check if port is commonly used."""
        common_ports = {
            80, 443, 22, 21, 25, 53, 110, 143, 993, 995,
            23, 135, 139, 445, 3389, 5900, 8080, 8443
        }
        return port in common_ports
    
    def _is_common_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is common/legitimate."""
        common_ua_indicators = [
            'Mozilla/5.0', 'Chrome/', 'Safari/', 'Edge/',
            'Firefox/', 'Opera/', 'iPhone', 'Android'
        ]
        
        # If it contains common browser indicators, likely legitimate
        return any(indicator in user_agent for indicator in common_ua_indicators)
    
    def _has_threat_context(self, content: str, ioc: str) -> bool:
        """Check if IOC appears in threatening context."""
        ioc_pos = content.lower().find(ioc.lower())
        if ioc_pos == -1:
            return False
        
        # Check surrounding context (100 characters before and after)
        start = max(0, ioc_pos - 100)
        end = min(len(content), ioc_pos + len(ioc) + 100)
        context = content[start:end].lower()
        
        return bool(self.threat_context_pattern.search(context))
    
    def _has_benign_context(self, content: str, ioc: str) -> bool:
        """Check if IOC appears in benign context."""
        ioc_pos = content.lower().find(ioc.lower())
        if ioc_pos == -1:
            return False
        
        start = max(0, ioc_pos - 100)
        end = min(len(content), ioc_pos + len(ioc) + 100)
        context = content[start:end].lower()
        
        return bool(self.benign_context_pattern.search(context))
    
    def _detect_threat_context(self, content: str) -> bool:
        """Detect if content contains threat intelligence context."""
        return bool(self.threat_context_pattern.search(content))
    
    def _calculate_confidence_scores(self, content: str, result: IOCResult) -> Dict[str, float]:
        """Calculate confidence scores for each IOC type."""
        confidence_scores = {}
        
        for ioc_type, iocs in result.to_dict().items():
            if not iocs:
                continue
            
            base_score = self.base_confidence_scores.get(ioc_type, 0.5)
            
            # Adjust based on threat context
            threat_context_count = sum(1 for ioc in iocs 
                                     if self._has_threat_context(content, ioc))
            threat_context_ratio = threat_context_count / len(iocs)
            
            # Adjust based on benign context
            benign_context_count = sum(1 for ioc in iocs 
                                     if self._has_benign_context(content, ioc))
            benign_context_ratio = benign_context_count / len(iocs)
            
            # Calculate final confidence
            confidence = base_score
            confidence += 0.3 * threat_context_ratio # Boost for threat context
            confidence -= 0.4 * benign_context_ratio # Reduce for benign context
            
            # Ensure confidence is within bounds
            confidence = max(0.0, min(1.0, confidence))
            confidence_scores[ioc_type] = confidence
        
        return confidence_scores
    
    def _filter_by_confidence(self, result: IOCResult, confidence_scores: Dict[str, float]) -> IOCResult:
        """Filter IOCs based on confidence threshold."""
        filtered_result = IOCResult()
        
        for ioc_type, iocs in result.to_dict().items():
            if ioc_type in confidence_scores:
                if confidence_scores[ioc_type] >= self.confidence_threshold:
                    setattr(filtered_result, ioc_type, iocs)
        
        # Preserve metadata
        filtered_result.extraction_metadata = result.extraction_metadata
        
        return filtered_result
    
    def export_iocs_to_file(self, result: IOCResult, filepath: str, format_type: str = "json") -> bool:
        """
        Export IOCs to file in specified format.
        Supports JSON, CSV, and STIX formats for threat intelligence sharing.
        """
        try:
            if format_type.lower() == "json":
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(result.to_json())
            
            elif format_type.lower() == "csv":
                import csv
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['IOC_Type', 'IOC_Value', 'Confidence'])
                    
                    confidence_scores = result.extraction_metadata.get('confidence_scores', {})
                    for ioc_type, iocs in result.to_dict().items():
                        confidence = confidence_scores.get(ioc_type, 0.5)
                        for ioc in iocs:
                            writer.writerow([ioc_type, ioc, confidence])
            
            elif format_type.lower() == "txt":
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write("# Threat Intelligence IOCs\n")
                    f.write(f"# Extracted at: {result.extraction_metadata.get('extracted_at', 'Unknown')}\n")
                    f.write(f"# Source: {result.extraction_metadata.get('source_url', 'Unknown')}\n\n")
                    
                    for ioc_type, iocs in result.to_dict().items():
                        if iocs:
                            f.write(f"## {ioc_type.upper().replace('_', ' ')}\n")
                            for ioc in iocs:
                                f.write(f"{ioc}\n")
                            f.write("\n")
            
            logger.info(f"IOCs exported to {filepath} in {format_type} format")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting IOCs to file: {e}")
            return False
    
    def get_ioc_statistics(self, result: IOCResult) -> Dict[str, Any]:
        """Get comprehensive statistics about extracted IOCs."""
        stats = {
            'total_iocs': result.get_total_count(),
            'extraction_time': result.extraction_metadata.get('processing_time', 0),
            'confidence_scores': result.extraction_metadata.get('confidence_scores', {}),
            'ioc_counts': {},
            'high_confidence_iocs': len(result.get_high_confidence_iocs()),
            'threat_context_detected': result.extraction_metadata.get('threat_context_detected', False)
        }
        
        # Count IOCs by type
        for ioc_type, iocs in result.to_dict().items():
            if iocs:
                stats['ioc_counts'][ioc_type] = len(iocs)
        
        return stats


# Main function for compatibility with existing code
def extract_iocs(content: str, custom_patterns: Optional[Dict[str, str]] = None) -> Dict[str, List[str]]:
    """
    Legacy function for backward compatibility.
    Use ThreatIntelligenceIOCExtractor.extract_iocs_from_feed_content() for new implementations.
    """
    extractor = ThreatIntelligenceIOCExtractor(custom_patterns)
    result = extractor.extract_iocs_from_feed_content(content)
    return result.to_dict()


# Example usage for testing
if __name__ == "__main__":
    # Test the enhanced IOC extractor
    test_content = """
    THREAT INTELLIGENCE REPORT - APT Campaign Analysis
    
    The threat actors used the following infrastructure:
    C2 IPs: 203.0.113.45, 185.220.101.45
    Malicious domains: evil-domain.com, malware-c2.badactor.net
    Payload URLs: http://malicious-site.com/payload.exe
    
    File indicators:
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Malware: backdoor.exe, keylogger.bat
    
    CVE: CVE-2023-12345
    Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    MITRE: T1055.001
    """
    
    extractor = ThreatIntelligenceIOCExtractor()
    result = extractor.extract_iocs_from_feed_content(test_content, "test_feed", "rss")
    
    print("🔍 Extracted IOCs:")
    print(json.dumps(result.to_dict(), indent=2))
    
    print("\n📊 Statistics:")
    stats = extractor.get_ioc_statistics(result)
    print(json.dumps(stats, indent=2))

EnhancedIOCExtractor = ThreatIntelligenceIOCExtractor