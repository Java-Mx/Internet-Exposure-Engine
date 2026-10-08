
import pickle
from typing import Dict, List, Any, Set, Tuple, Optional
import networkx as nx
from datetime import datetime
from sqlalchemy.orm import Session

from config.logging_config import get_logger

logger = get_logger(__name__)


class GraphBuilder:

    def __init__(self):
        self.logger = logger
        self.graph = nx.Graph()


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
        from database.models import Asset, GitHubExposure, Breach

        self.logger.info("Building graph from database...")


        query = session.query(Asset)
        if limit:
            query = query.limit(limit)

        assets = query.all()
        self.logger.info(f"Processing {len(assets)} assets...")


        for asset in assets:
            self._add_asset_to_graph(asset)


        github_exposures = session.query(GitHubExposure).all()
        for exposure in github_exposures:
            self._add_github_exposure_to_graph(exposure)


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
        self.logger.info(f"Building graph from {len(assets)} assets...")


        for asset in assets:
            self._add_asset_dict_to_graph(asset)


        if github_exposures:
            for exposure in github_exposures:
                self._add_github_exposure_dict_to_graph(exposure)


        if breaches:
            for breach in breaches:
                self._add_breach_dict_to_graph(breach)

        self.logger.info(f"Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")

        return self.graph

    def _add_asset_to_graph(self, asset):
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
        ip = asset.get('ip')
        domain = asset.get('domain')
        port = asset.get('port')
        service = asset.get('service')
        asn = asset.get('asn')


        if ip:
            self.graph.add_node(
                f"ip:{ip}",
                type='ip',
                ip=ip,
                country=asset.get('country'),
                discovered_at=asset.get('discovered_at')
            )
            self.node_types['ip'].add(f"ip:{ip}")


        if domain:
            self.graph.add_node(
                f"domain:{domain}",
                type='domain',
                domain=domain
            )
            self.node_types['domain'].add(f"domain:{domain}")


            if ip:
                self.graph.add_edge(
                    f"ip:{ip}",
                    f"domain:{domain}",
                    relationship='resolves_to'
                )


        if service and port:
            service_id = f"service:{ip}:{port}:{service}"
            self.graph.add_node(
                service_id,
                type='service',
                service=service,
                port=port
            )
            self.node_types['service'].add(service_id)


            if ip:
                self.graph.add_edge(
                    f"ip:{ip}",
                    service_id,
                    relationship='hosts_service'
                )


        if asn:
            asn_id = f"asn:{asn}"
            self.graph.add_node(
                asn_id,
                type='asn',
                asn=asn
            )
            self.node_types['asn'].add(asn_id)


            if ip:
                self.graph.add_edge(
                    f"ip:{ip}",
                    asn_id,
                    relationship='belongs_to_asn'
                )

    def _add_github_exposure_to_graph(self, exposure):
        exposure_dict = {
            'secret_type': exposure.secret_type,
            'repo_url': exposure.repo_url,
            'file_path': exposure.file_path,
            'commit_hash': exposure.commit_hash
        }
        self._add_github_exposure_dict_to_graph(exposure_dict)

    def _add_github_exposure_dict_to_graph(self, exposure: Dict[str, Any]):
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


            if '@' in repo_url:
                email_domain = repo_url.split('@')[1].split('/')[0]
                email_domain_id = f"email_domain:{email_domain}"

                self.graph.add_node(
                    email_domain_id,
                    type='email_domain',
                    domain=email_domain
                )
                self.node_types['email_domain'].add(email_domain_id)


                self.graph.add_edge(
                    credential_id,
                    email_domain_id,
                    relationship='associated_with_email_domain'
                )

    def _add_breach_to_graph(self, breach):
        breach_dict = {
            'email': breach.email,
            'breach_name': breach.breach_name,
            'breach_date': breach.breach_date,
            'pwn_count': breach.pwn_count
        }
        self._add_breach_dict_to_graph(breach_dict)

    def _add_breach_dict_to_graph(self, breach: Dict[str, Any]):
        email = breach.get('email')

        if email and '@' in email:
            email_domain = email.split('@')[1]
            email_domain_id = f"email_domain:{email_domain}"


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
        return list(self.node_types.get(node_type, set()))

    def get_neighbors(self, node_id: str) -> List[str]:
        if node_id in self.graph:
            return list(self.graph.neighbors(node_id))
        return []

    def get_subgraph(self, node_ids: List[str]) -> nx.Graph:
        return self.graph.subgraph(node_ids).copy()

    def get_graph_statistics(self) -> Dict[str, Any]:
        if self.graph.number_of_nodes() == 0:
            return {
                'total_nodes': 0,
                'total_edges': 0,
                'nodes_by_type': {},
                'is_connected': False,
                'number_of_components': 0,
                'density': 0,
                'average_degree': 0
            }

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
            'average_degree': sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes()
        }

        return stats

    def save_graph(self, filepath: str):
        """Persist graph to disk using pickle (nx.write_gpickle removed in NetworkX 3.x)."""
        with open(filepath, "wb") as f:
            pickle.dump(self.graph, f, protocol=pickle.HIGHEST_PROTOCOL)
        self.logger.info(f"Graph saved to {filepath}")

    def load_graph(self, filepath: str):
        """Load graph from disk using pickle."""
        with open(filepath, "rb") as f:
            self.graph = pickle.load(f)

        for node_type in self.node_types.keys():
            self.node_types[node_type] = set()

        for node, data in self.graph.nodes(data=True):
            node_type = data.get('type')
            if node_type in self.node_types:
                self.node_types[node_type].add(node)

        self.logger.info(f"Graph loaded from {filepath}")