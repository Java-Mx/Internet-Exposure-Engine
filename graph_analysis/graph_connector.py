"""
Graph Analysis Connector
========================
Bridges the live inference pipeline with the Graph Database.
Dynamically maps relationships (Domain <-> IP <-> ASN) into SQLite,
then runs RiskPropagator using NetworkX to compute community risk.
"""

import sys
import logging
import networkx as nx
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

from records.db_manager import get_db_connection
from graph_analysis.risk_propagator import RiskPropagator

logger = logging.getLogger(__name__)


def update_graph_and_get_risk(domain: str, ip: str = None, asn: str = None, initial_risk: float = 0.0) -> float:
    """
    Inserts/updates the node relationships in SQLite, builds a localized NetworkX subgraph,
    runs RiskPropagator, and returns the propagated graph risk for the domain.
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # 1. Update Nodes & Edges
            # Domain node
            cursor.execute(
                "INSERT INTO graph_nodes (node_id, node_type, initial_risk) VALUES (?, 'domain', ?) "
                "ON CONFLICT(node_id) DO UPDATE SET initial_risk = max(initial_risk, excluded.initial_risk)",
                (f"domain:{domain}", initial_risk)
            )

            if ip:
                cursor.execute(
                    "INSERT INTO graph_nodes (node_id, node_type, initial_risk) VALUES (?, 'ip', 0.0) "
                    "ON CONFLICT(node_id) DO UPDATE SET last_updated = CURRENT_TIMESTAMP",
                    (f"ip:{ip}",)
                )
                cursor.execute(
                    "INSERT INTO graph_edges (source_id, target_id, relation_type) VALUES (?, ?, 'resolves_to') "
                    "ON CONFLICT(source_id, target_id, relation_type) DO UPDATE SET relation_type = excluded.relation_type",
                    (f"ip:{ip}", f"domain:{domain}")
                )

            if asn:
                cursor.execute(
                    "INSERT INTO graph_nodes (node_id, node_type, initial_risk) VALUES (?, 'asn', 0.0) "
                    "ON CONFLICT(node_id) DO UPDATE SET last_updated = CURRENT_TIMESTAMP",
                    (f"asn:{asn}",)
                )
                if ip:
                    cursor.execute(
                        "INSERT INTO graph_edges (source_id, target_id, relation_type) VALUES (?, ?, 'belongs_to_asn') "
                        "ON CONFLICT(source_id, target_id, relation_type) DO UPDATE SET relation_type = excluded.relation_type",
                        (f"ip:{ip}", f"asn:{asn}")
                    )

            conn.commit()

            # 2. Build NetworkX Graph (fetching all connected infrastructure)
            cursor.execute("SELECT node_id, initial_risk FROM graph_nodes")
            nodes = cursor.fetchall()

            cursor.execute("SELECT source_id, target_id FROM graph_edges")
            edges = cursor.fetchall()

            # Build graph from plain Python data — NOT from connection/cursor objects
            G = nx.Graph()
            initial_risks = {}
            for n in nodes:
                node_id = n["node_id"]
                risk = n["initial_risk"]
                G.add_node(node_id)
                if risk > 0:
                    initial_risks[node_id] = risk

            for e in edges:
                G.add_edge(e["source_id"], e["target_id"])

            # cursor is no longer needed; close it before releasing the connection
            cursor.close()

        # conn is now fully closed (context manager __exit__ called close())
        # 3. Run Risk Propagator (pure in-memory, no DB connection involved)
        rp = RiskPropagator(graph=G, decay_factor=0.7)
        rp.set_initial_risks(initial_risks)
        rp.propagate_risk()

        domain_risk = rp.get_propagated_risk(f"domain:{domain}")
        return domain_risk

    except Exception as e:
        logger.error(f"Graph connector failed: {e}")
        return 0.0
