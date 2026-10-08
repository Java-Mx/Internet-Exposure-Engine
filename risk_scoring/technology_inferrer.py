
import re
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

from config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class TechCategory:
    category: str
    family: str
    confidence: float
    cpe_search_terms: List[str] = field(default_factory=list)
    reason: str = ""


DOMAIN_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r"\.wordpress\.com$", "category": "wordpress", "family": "cms",
     "confidence": 0.90, "cpe_terms": ["wordpress"], "reason": "WordPress.com hosted domain"},
    {"pattern": r"\.wixsite\.com$|\.wix\.com$", "category": "wix", "family": "cms",
     "confidence": 0.90, "cpe_terms": ["wix"], "reason": "Wix-hosted domain"},
    {"pattern": r"\.squarespace\.com$", "category": "squarespace", "family": "cms",
     "confidence": 0.90, "cpe_terms": ["squarespace"], "reason": "Squarespace-hosted domain"},
    {"pattern": r"\.shopify\.com$|\.myshopify\.com$", "category": "shopify", "family": "ecommerce",
     "confidence": 0.90, "cpe_terms": ["shopify"], "reason": "Shopify-hosted domain"},
    {"pattern": r"\.herokuapp\.com$", "category": "heroku", "family": "cloud_platform",
     "confidence": 0.85, "cpe_terms": ["heroku"], "reason": "Heroku cloud platform"},
    {"pattern": r"\.azurewebsites\.net$|\.azure\.com$", "category": "azure", "family": "cloud_platform",
     "confidence": 0.85, "cpe_terms": ["microsoft", "azure"], "reason": "Microsoft Azure hosting"},
    {"pattern": r"\.amazonaws\.com$|\.aws\.amazon\.com$", "category": "aws", "family": "cloud_platform",
     "confidence": 0.85, "cpe_terms": ["amazon", "aws"], "reason": "AWS-hosted infrastructure"},
    {"pattern": r"\.appspot\.com$|\.run\.app$", "category": "gcp", "family": "cloud_platform",
     "confidence": 0.85, "cpe_terms": ["google", "cloud"], "reason": "Google Cloud Platform hosting"},
    {"pattern": r"\.github\.io$", "category": "github_pages", "family": "static_hosting",
     "confidence": 0.90, "cpe_terms": ["github"], "reason": "GitHub Pages static hosting"},
    {"pattern": r"\.netlify\.app$", "category": "netlify", "family": "static_hosting",
     "confidence": 0.90, "cpe_terms": ["netlify"], "reason": "Netlify static hosting"},
    {"pattern": r"\.vercel\.app$", "category": "vercel", "family": "static_hosting",
     "confidence": 0.90, "cpe_terms": ["vercel"], "reason": "Vercel hosting"},
]

URL_PATH_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r"/wp-admin|/wp-content|/wp-includes|/wp-login",
     "category": "wordpress", "family": "cms",
     "confidence": 0.80, "cpe_terms": ["wordpress"],
     "reason": "WordPress path patterns detected"},
    {"pattern": r"/administrator|/components/com_|index\.php\?option=com_",
     "category": "joomla", "family": "cms",
     "confidence": 0.75, "cpe_terms": ["joomla"],
     "reason": "Joomla path patterns detected"},
    {"pattern": r"/sites/default|/modules/system|/core/misc/drupal",
     "category": "drupal", "family": "cms",
     "confidence": 0.75, "cpe_terms": ["drupal"],
     "reason": "Drupal path patterns detected"},
    {"pattern": r"/phpmyadmin|/pma",
     "category": "phpmyadmin", "family": "database_admin",
     "confidence": 0.80, "cpe_terms": ["phpmyadmin"],
     "reason": "phpMyAdmin interface detected"},
    {"pattern": r"\.aspx$|\.ashx$|/__doPostBack",
     "category": "asp_net", "family": "application_framework",
     "confidence": 0.70, "cpe_terms": ["microsoft", "asp.net"],
     "reason": "ASP.NET framework patterns"},
    {"pattern": r"\.jsp$|/servlet/|/j_spring_security",
     "category": "java_web", "family": "application_framework",
     "confidence": 0.70, "cpe_terms": ["apache", "tomcat", "java"],
     "reason": "Java web application patterns"},
    {"pattern": r"\.php$|\.php\?",
     "category": "php", "family": "application_framework",
     "confidence": 0.60, "cpe_terms": ["php"],
     "reason": "PHP application patterns"},
]

PORT_SERVICE_PATTERNS: Dict[int, Dict[str, Any]] = {
    21:    {"category": "ftp_server", "family": "file_transfer",
            "confidence": 0.80, "cpe_terms": ["ftp"], "reason": "FTP service"},
    22:    {"category": "ssh_server", "family": "remote_access",
            "confidence": 0.80, "cpe_terms": ["openssh", "ssh"], "reason": "SSH service"},
    25:    {"category": "smtp_server", "family": "mail_server",
            "confidence": 0.75, "cpe_terms": ["smtp", "postfix", "exim"],
            "reason": "SMTP mail service"},
    3306:  {"category": "mysql", "family": "database",
            "confidence": 0.80, "cpe_terms": ["mysql", "mariadb"], "reason": "MySQL/MariaDB"},
    5432:  {"category": "postgresql", "family": "database",
            "confidence": 0.80, "cpe_terms": ["postgresql"], "reason": "PostgreSQL"},
    6379:  {"category": "redis", "family": "database",
            "confidence": 0.80, "cpe_terms": ["redis"], "reason": "Redis cache/store"},
    27017: {"category": "mongodb", "family": "database",
            "confidence": 0.80, "cpe_terms": ["mongodb"], "reason": "MongoDB"},
    9200:  {"category": "elasticsearch", "family": "search_engine",
            "confidence": 0.80, "cpe_terms": ["elasticsearch"], "reason": "Elasticsearch"},
    3389:  {"category": "rdp", "family": "remote_access",
            "confidence": 0.80, "cpe_terms": ["rdp", "microsoft"],
            "reason": "Remote Desktop Protocol"},
}


DEFAULT_WEB_TECH = TechCategory(
    category="generic_web_server",
    family="web_server",
    confidence=0.30,
    cpe_search_terms=["apache", "nginx", "iis", "http"],
    reason="Standard web server (generic inference)",
)


class TechnologyInferrer:

    def infer(self, asset: Dict[str, Any]) -> List[TechCategory]:
        categories: Dict[str, TechCategory] = {}
        domain = (asset.get("domain") or "").lower()
        port = asset.get("port", 443)
        url = (asset.get("full_url") or asset.get("url") or "").lower()
        service = (asset.get("service") or "").lower()


        for dp in DOMAIN_PATTERNS:
            if re.search(dp["pattern"], domain):
                cat = dp["category"]
                if cat not in categories or dp["confidence"] > categories[cat].confidence:
                    categories[cat] = TechCategory(
                        category=cat,
                        family=dp["family"],
                        confidence=dp["confidence"],
                        cpe_search_terms=dp["cpe_terms"],
                        reason=dp["reason"],
                    )


        for up in URL_PATH_PATTERNS:
            if re.search(up["pattern"], url, re.IGNORECASE):
                cat = up["category"]
                if cat not in categories or up["confidence"] > categories[cat].confidence:
                    categories[cat] = TechCategory(
                        category=cat,
                        family=up["family"],
                        confidence=up["confidence"],
                        cpe_search_terms=up["cpe_terms"],
                        reason=up["reason"],
                    )


        if port in PORT_SERVICE_PATTERNS:
            info = PORT_SERVICE_PATTERNS[port]
            cat = info["category"]
            if cat not in categories or info["confidence"] > categories[cat].confidence:
                categories[cat] = TechCategory(
                    category=cat,
                    family=info["family"],
                    confidence=info["confidence"],
                    cpe_search_terms=info["cpe_terms"],
                    reason=info["reason"],
                )


        service_hints = {
            "https": ("generic_web_server", "web_server", 0.30, ["apache", "nginx", "iis"]),
            "http": ("generic_web_server", "web_server", 0.30, ["apache", "nginx", "iis"]),
            "ftp": ("ftp_server", "file_transfer", 0.75, ["ftp"]),
            "ssh": ("ssh_server", "remote_access", 0.75, ["openssh"]),
            "telnet": ("telnet_server", "remote_access", 0.80, ["telnet"]),
            "mysql": ("mysql", "database", 0.80, ["mysql"]),
            "rdp": ("rdp", "remote_access", 0.80, ["rdp"]),
        }
        if service in service_hints:
            cat, fam, conf, terms = service_hints[service]
            if cat not in categories or conf > categories[cat].confidence:
                categories[cat] = TechCategory(
                    category=cat, family=fam, confidence=conf,
                    cpe_search_terms=terms,
                    reason=f"Service string indicates {cat}",
                )


        if not categories and port in (80, 443, 8080, 8443):
            categories["generic_web_server"] = DEFAULT_WEB_TECH

        result = sorted(categories.values(), key=lambda c: c.confidence, reverse=True)
        return result