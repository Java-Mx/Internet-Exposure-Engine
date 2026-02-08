"""
HaveIBeenPwned (HIBP) connector for breach data.
Provides access to breach information and compromised account data.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime

from .base_connector import BaseConnector
from config.settings import get_settings

settings = get_settings()


class HIBPConnector(BaseConnector):
    """
    Connector for HaveIBeenPwned API.
    Provides breach confirmation and data breach information.
    """
    
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize HIBP connector.
        
        Args:
            api_key: HIBP API key (defaults to settings)
        """
        api_key = api_key or settings.HIBP_API_KEY
        super().__init__(api_key=api_key, rate_limit=0.05)  # 1 request per 1.5 seconds
        
        if api_key:
            self.session.headers.update({
                'hibp-api-key': api_key
            })
        else:
            self.logger.warning("HIBP API key not configured. Limited functionality.")
    
    def fetch_data(self) -> List[Dict[str, Any]]:
        """
        Fetch all breaches from HIBP.
        
        Returns:
            List of all breaches
        """
        url = f"{self.BASE_URL}/breaches"
        
        self.logger.info("Fetching all breaches from HIBP")
        data = self._make_request(url)
        
        if isinstance(data, list):
            self.logger.info(f"Fetched {len(data)} breaches")
            return data
        
        return []
    
    def check_account(self, account: str) -> List[Dict[str, Any]]:
        """
        Check if an account (email) has been breached.
        Requires API key.
        
        Args:
            account: Email address to check
        
        Returns:
            List of breaches affecting this account
        """
        if not self.api_key:
            self.logger.error("HIBP API key required for account checks")
            return []
        
        url = f"{self.BASE_URL}/breachedaccount/{account}"
        params = {'truncateResponse': 'false'}
        
        self.logger.info(f"Checking HIBP for account: {account}")
        data = self._make_request(url, params=params)
        
        if isinstance(data, list):
            self.logger.info(f"Account found in {len(data)} breaches")
            return data
        
        return []
    
    def check_domain(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get breaches for a specific domain.
        
        Args:
            domain: Domain to check
        
        Returns:
            List of breaches affecting this domain
        """
        all_breaches = self.fetch_data()
        
        # Filter breaches by domain
        domain_breaches = [
            breach for breach in all_breaches
            if breach.get('Domain', '').lower() == domain.lower()
        ]
        
        self.logger.info(f"Found {len(domain_breaches)} breaches for domain: {domain}")
        return domain_breaches
    
    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize HIBP breach data to canonical format.
        
        Args:
            raw_data: Raw HIBP breach data
        
        Returns:
            Normalized breach data
        """
        # Parse date strings
        breach_date = raw_data.get('BreachDate')
        added_date = raw_data.get('AddedDate')
        modified_date = raw_data.get('ModifiedDate')
        
        try:
            breach_date = datetime.strptime(breach_date, '%Y-%m-%d').date() if breach_date else None
        except:
            breach_date = None
        
        try:
            added_date = datetime.fromisoformat(added_date.replace('Z', '+00:00')).date() if added_date else None
        except:
            added_date = None
        
        try:
            modified_date = datetime.fromisoformat(modified_date.replace('Z', '+00:00')).date() if modified_date else None
        except:
            modified_date = None
        
        normalized = {
            'breach_name': raw_data.get('Name'),
            'title': raw_data.get('Title'),
            'domain': raw_data.get('Domain'),
            'breach_date': breach_date,
            'added_date': added_date,
            'modified_date': modified_date,
            'pwn_count': raw_data.get('PwnCount', 0),
            'description': raw_data.get('Description', ''),
            'data_classes': raw_data.get('DataClasses', []),
            'is_verified': raw_data.get('IsVerified', False),
            'is_sensitive': raw_data.get('IsSensitive', False),
            'metadata': {
                'is_fabricated': raw_data.get('IsFabricated', False),
                'is_spam_list': raw_data.get('IsSpamList', False),
                'is_retired': raw_data.get('IsRetired', False),
                'logo_path': raw_data.get('LogoPath')
            }
        }
        
        return normalized
    
    def fetch_and_normalize(self) -> List[Dict[str, Any]]:
        """
        Fetch and normalize all breaches in one call.
        
        Returns:
            List of normalized breach records
        """
        raw_breaches = self.fetch_data()
        normalized_list = []
        
        for breach in raw_breaches:
            normalized = self.normalize_data(breach)
            if normalized:
                normalized_list.append(normalized)
        
        return normalized_list
    
    def check_and_normalize_account(self, account: str) -> List[Dict[str, Any]]:
        """
        Check account and normalize results.
        
        Args:
            account: Email address to check
        
        Returns:
            List of normalized breach records affecting this account
        """
        raw_breaches = self.check_account(account)
        normalized_list = []
        
        for breach in raw_breaches:
            normalized = self.normalize_data(breach)
            if normalized:
                # Add account information
                normalized['affected_account'] = account
                normalized_list.append(normalized)
        
        return normalized_list
