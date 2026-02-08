"""
Graph builder for constructing asset relationship graphs.
Creates nodes for IPs, domains, services, credentials and edges for relationships.
"""

from typing import Dict, List, Any, Set, Tuple, Optional
import networkx as nx
from datetime import datetime
from sqlalchemy.orm import Session

from config.logging_config import get_logger

logger = get_logger(__name__)


class GraphBuilder:
    """
    Builds a NetworkX graph from asset data with various relationship types.
    """
    
    def __init__(self):
        """Initialize graph builder."""
        self.logger = logger
        self.graph = nx.Graph()
        
        # Track node types
        self.node_types = {
            'ip': set(),
            'domain': set(),
            'service': set(),
            'credential': set(),
            'asn': set(),
            'email_domain': set()
        }
    
    def build_from_database(
        self,
        session: Session,
        limit: Optional[int] = None
    ) -> nx.Graph:
        """
        Build graph from database assets.
        
        Args:
            session: Database session
            limit: Maximum number of assets to process
        
        Returns:
            NetworkX graph
        """
        from database.models import Asset, GitHubExposure, Breach
        
        self.logger.info("Building graph from database...")
        
        # Fetch assets
        query = session.query(Asset)
        if limit:
            query = query.limit(limit)
        
        assets = query.all()
        self.logger.info(f"Processing {len(assets)} assets...")
        
        # Add nodes and edges
        for asset in assets:
            self._add_asset_to_graph(asset)
        
        # Fetch GitHub exposures
        github_exposures = session.query(GitHubExposure).all()
        for exposure in github_exposures:
            self._add_github_exposure_to_graph(exposure)
        
        # Fetch breaches
        breaches = session.query(Breach).all()
        for breach in breaches:
            self._add_breach_to_graph(breach)
        
        self.logger.info(f"Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        
        return self.graph
    
    def build_from_assets(
        self,
        assets: List[Dict[str, Any]],
        github_exposures: Optional[List[Dict[str, Any]]] = None,
        breaches: Optional[List[Dict[str, Any]]] = None
    ) -> nx.Graph:
        """
        Build graph from asset dictionaries.
        
        Args:
            assets: List of asset dictionaries
            github_exposures: List of GitHub exposure dictionaries
            breaches: List of breach dictionaries
        
        Returns:
            NetworkX graph
        """
        self.logger.info(f"Building graph from {len(assets)} assets...")
        
        # Add assets
        for asset in assets:
            self._add_asset_dict_to_graph(asset)
        
        # Add GitHub exposures
        if github_exposures:
            for exposure in github_exposures:
                self._add_github_exposure_dict_to_graph(exposure)
        
        # Add breaches
        if breaches:
            for breach in breaches:
                self._add_breach_dict_to_graph(breach)
        
        self.logger.info(f"Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        
        return self.graph
    
    def _add_asset_to_graph(self, asset):
        """Add asset from database model to graph."""
        asset_dict = {
            'ip': asset.ip,
            'domain': asset.domain,
            'port': asset.port,
            'service': asset.service,
            'asn': asset.asn,
            'country': asset.country,
            'discovered_at': asset.discovered_at,
            'source': asset.source
        }
        self._add_asset_dict_to_graph(asset_dict)
    
    def _add_asset_dict_to_graph(self, asset: Dict[str, Any]):
        """Add asset dictionary to graph."""
        ip = asset.get('ip')
        domain = asset.get('domain')
        port = asset.get('port')
        service = asset.get('service')
        asn = asset.get('asn')
        
        # Add IP node
        if ip:
            self.graph.add_node(
                f"ip:{ip}",
                type='ip',
                ip=ip,
                country=asset.get('country'),
                discovered_at=asset.get('discovered_at')
            )
            self.node_types['ip'].add(f"ip:{ip}")
        
        # Add domain node
        if domain:
            self.graph.add_node(
                f"domain:{domain}",
                type='domain',
                domain=domain
            )
            self.node_types['domain'].add(f"domain:{domain}")
            
            # Link IP to domain
            if ip:
                self.graph.add_edge(
                    f"ip:{ip}",
                    f"domain:{domain}",
                    relationship='resolves_to'
                )
        
        # Add service node
        if service and port:
            service_id = f"service:{ip}:{port}:{service}"
            self.graph.add_node(
                service_id,
                type='service',
                service=service,
                port=port
            )
            self.node_types['service'].add(service_id)
            
            # Link IP to service
            if ip:
                self.graph.add_edge(
                    f"ip:{ip}",
                    service_id,
                    relationship='hosts_service'
                )
        
        # Add ASN node
        if asn:
            asn_id = f"asn:{asn}"
            self.graph.add_node(
                asn_id,
                type='asn',
                asn=asn
            )
            self.node_types['asn'].add(asn_id)
            
            # Link IP to ASN
            if ip:
                self.graph.add_edge(
                    f"ip:{ip}",
                    asn_id,
                    relationship='belongs_to_asn'
                )
    
    def _add_github_exposure_to_graph(self, exposure):
        """Add GitHub exposure from database model to graph."""
        exposure_dict = {
            'secret_type': exposure.secret_type,
            'repo_url': exposure.repo_url,
            'file_path': exposure.file_path,
            'commit_hash': exposure.commit_hash
        }
        self._add_github_exposure_dict_to_graph(exposure_dict)
    
    def _add_github_exposure_dict_to_graph(self, exposure: Dict[str, Any]):
        """Add GitHub exposure dictionary to graph."""
        secret_type = exposure.get('secret_type')
        repo_url = exposure.get('repo_url')
        
        if secret_type and repo_url:
            credential_id = f"credential:{secret_type}:{repo_url}"
            self.graph.add_node(
                credential_id,
                type='credential',
                secret_type=secret_type,
                repo_url=repo_url,
                file_path=exposure.get('file_path'),
                commit_hash=exposure.get('commit_hash')
            )
            self.node_types['credential'].add(credential_id)
            
            # Extract email domain from repo URL if possible
            if '@' in repo_url:
                email_domain = repo_url.split('@')[1].split('/')[0]
                email_domain_id = f"email_domain:{email_domain}"
                
                self.graph.add_node(
                    email_domain_id,
                    type='email_domain',
                    domain=email_domain
                )
                self.node_types['email_domain'].add(email_domain_id)
                
                # Link credential to email domain
                self.graph.add_edge(
                    credential_id,
                    email_domain_id,
                    relationship='associated_with_email_domain'
                )
    
    def _add_breach_to_graph(self, breach):
        """Add breach from database model to graph."""
        breach_dict = {
            'email': breach.email,
            'breach_name': breach.breach_name,
            'breach_date': breach.breach_date,
            'pwn_count': breach.pwn_count
        }
        self._add_breach_dict_to_graph(breach_dict)
    
    def _add_breach_dict_to_graph(self, breach: Dict[str, Any]):
        """Add breach dictionary to graph."""
        email = breach.get('email')
        
        if email and '@' in email:
            email_domain = email.split('@')[1]
            email_domain_id = f"email_domain:{email_domain}"
            
            # Add email domain node
            self.graph.add_node(
                email_domain_id,
                type='email_domain',
                domain=email_domain,
                is_breached=True,
                breach_name=breach.get('breach_name'),
                breach_date=breach.get('breach_date'),
                pwn_count=breach.get('pwn_count')
            )
            self.node_types['email_domain'].add(email_domain_id)
    
    def get_node_by_type(self, node_type: str) -> List[str]:
        """
        Get all nodes of a specific type.
        
        Args:
            node_type: Type of node (ip, domain, service, credential, asn, email_domain)
        
        Returns:
            List of node IDs
        """
        return list(self.node_types.get(node_type, set()))
    
    def get_neighbors(self, node_id: str) -> List[str]:
        """
        Get neighbors of a node.
        
        Args:
            node_id: Node identifier
        
        Returns:
            List of neighbor node IDs
        """
        if node_id in self.graph:
            return list(self.graph.neighbors(node_id))
        return []
    
    def get_subgraph(self, node_ids: List[str]) -> nx.Graph:
        """
        Get subgraph containing specific nodes.
        
        Args:
            node_ids: List of node IDs
        
        Returns:
            Subgraph
        """
        return self.graph.subgraph(node_ids).copy()
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """
        Get graph statistics.
        
        Returns:
            Dictionary with graph statistics
        """
        stats = {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'nodes_by_type': {
                node_type: len(nodes)
                for node_type, nodes in self.node_types.items()
            },
            'is_connected': nx.is_connected(self.graph),
            'number_of_components': nx.number_connected_components(self.graph),
            'density': nx.density(self.graph),
            'average_degree': sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes() if self.graph.number_of_nodes() > 0 else 0
        }
        
        return stats
    
    def save_graph(self, filepath: str):
        """
        Save graph to file.
        
        Args:
            filepath: Path to save graph
        """
        nx.write_gpickle(self.graph, filepath)
        self.logger.info(f"Graph saved to {filepath}")
    
    def load_graph(self, filepath: str):
        """
        Load graph from file.
        
        Args:
            filepath: Path to load graph from
        """
        self.graph = nx.read_gpickle(filepath)
        
        # Rebuild node type index
        for node_type in self.node_types.keys():
            self.node_types[node_type] = set()
        
        for node, data in self.graph.nodes(data=True):
            node_type = data.get('type')
            if node_type in self.node_types:
                self.node_types[node_type].add(node)
        
        self.logger.info(f"Graph loaded from {filepath}")
