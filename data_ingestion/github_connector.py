"""
GitHub Public Events API connector for detecting potential credential leaks.
Monitors public commits for exposed secrets and API keys.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import re

from .base_connector import BaseConnector
from config.settings import get_settings

settings = get_settings()


class GitHubConnector(BaseConnector):
    """
    Connector for GitHub Public Events API.
    Detects potential credential and secret exposures in public repositories.
    """
    
    BASE_URL = "https://api.github.com"
    
    # Patterns for detecting potential secrets
    SECRET_PATTERNS = {
        'api_key': re.compile(r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'password': re.compile(r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\'\s]{8,})', re.IGNORECASE),
        'token': re.compile(r'(?i)(token|auth)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
        'private_key': re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        'github_token': re.compile(r'ghp_[a-zA-Z0-9]{36}'),
        'slack_token': re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'),
    }
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub connector.
        
        Args:
            token: GitHub personal access token (defaults to settings)
        """
        token = token or settings.GITHUB_TOKEN
        super().__init__(rate_limit=1.0)  # 1 request per second (conservative)
        
        if token:
            self.session.headers.update({
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            })
        else:
            self.logger.warning("GitHub token not configured. Rate limits will be strict.")
    
    def fetch_data(self, event_type: str = 'PushEvent', limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch public events from GitHub.
        
        Args:
            event_type: Type of event to fetch (PushEvent, CreateEvent, etc.)
            limit: Maximum events to fetch
        
        Returns:
            List of events
        """
        url = f"{self.BASE_URL}/events"
        
        self.logger.info(f"Fetching GitHub public events")
        events = []
        page = 1
        
        while len(events) < limit:
            params = {'page': page, 'per_page': min(100, limit - len(events))}
            data = self._make_request(url, params=params)
            
            if not data:
                break
            
            # Filter by event type if specified
            if event_type:
                filtered = [e for e in data if e.get('type') == event_type]
            else:
                filtered = data
            
            events.extend(filtered)
            
            if len(data) < 100:  # No more pages
                break
            
            page += 1
        
        self.logger.info(f"Fetched {len(events)} events")
        return events[:limit]
    
    def search_code(self, query: str, per_page: int = 30) -> List[Dict[str, Any]]:
        """
        Search GitHub code for potential exposures.
        
        Args:
            query: Search query
            per_page: Results per page (max 100)
        
        Returns:
            List of code search results
        """
        url = f"{self.BASE_URL}/search/code"
        params = {
            'q': query,
            'per_page': min(per_page, 100)
        }
        
        self.logger.info(f"Searching GitHub code: {query}")
        data = self._make_request(url, params=params)
        
        if data and 'items' in data:
            return data['items']
        return []
    
    def detect_secrets(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect potential secrets in text using regex patterns.
        
        Args:
            text: Text to scan
        
        Returns:
            List of detected secrets with type and confidence
        """
        detections = []
        
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = pattern.finditer(text)
            for match in matches:
                detection = {
                    'type': secret_type,
                    'matched_text': match.group(0)[:50],  # Truncate for safety
                    'confidence': 0.7,  # Base confidence for regex match
                    'position': match.start()
                }
                
                # Increase confidence for specific patterns
                if secret_type in ['aws_key', 'github_token', 'private_key']:
                    detection['confidence'] = 0.9
                
                detections.append(detection)
        
        return detections
    
    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize GitHub event data to exposure format.
        
        Args:
            raw_data: Raw GitHub event
        
        Returns:
            Normalized exposure data
        """
        if raw_data.get('type') == 'PushEvent':
            repo = raw_data.get('repo', {})
            payload = raw_data.get('payload', {})
            commits = payload.get('commits', [])
            
            # Analyze commits for potential secrets
            exposures = []
            for commit in commits:
                message = commit.get('message', '')
                
                # Detect secrets in commit message
                secrets = self.detect_secrets(message)
                
                if secrets:
                    exposure = {
                        'repo_full_name': repo.get('name'),
                        'commit_sha': commit.get('sha'),
                        'file_path': None,  # Would need to fetch commit details
                        'exposure_type': secrets[0]['type'],
                        'confidence': secrets[0]['confidence'],
                        'discovered_at': datetime.utcnow(),
                        'metadata': {
                            'commit_message': message[:200],
                            'author': commit.get('author'),
                            'detections': secrets,
                            'event_id': raw_data.get('id')
                        }
                    }
                    exposures.append(exposure)
            
            return exposures if exposures else []
        
        elif 'name' in raw_data and 'path' in raw_data:  # Code search result
            # This is a code search result
            exposure = {
                'repo_full_name': raw_data.get('repository', {}).get('full_name'),
                'commit_sha': raw_data.get('sha'),
                'file_path': raw_data.get('path'),
                'exposure_type': 'code_search_match',
                'confidence': 0.6,
                'discovered_at': datetime.utcnow(),
                'metadata': {
                    'file_name': raw_data.get('name'),
                    'html_url': raw_data.get('html_url'),
                    'repository': raw_data.get('repository')
                }
            }
            return [exposure]
        
        return []
    
    def fetch_and_normalize(self, event_type: str = 'PushEvent', limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch and normalize GitHub events in one call.
        
        Args:
            event_type: Type of event to fetch
            limit: Maximum events to fetch
        
        Returns:
            List of normalized exposure records
        """
        raw_events = self.fetch_data(event_type, limit)
        all_exposures = []
        
        for event in raw_events:
            exposures = self.normalize_data(event)
            if isinstance(exposures, list):
                all_exposures.extend(exposures)
            elif exposures:
                all_exposures.append(exposures)
        
        self.logger.info(f"Detected {len(all_exposures)} potential exposures")
        return all_exposures
