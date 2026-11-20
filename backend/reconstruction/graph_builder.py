import networkx as nx

from backend.evidence.normalizer import entity_label
from backend.evidence.schema import EvidenceRecord, RelationshipRecord


class EvidenceGraphBuilder:
    @staticmethod
    def build(
        evidence: list[EvidenceRecord],
        relationships: list[RelationshipRecord],
    ) -> nx.DiGraph:
        graph = nx.DiGraph()
        for record in evidence:
            graph.add_node(
                record.evidence_id,
                evidence_id=record.evidence_id,
                type=record.type,
                label=entity_label(record),
                source_plugin=record.source_plugin,
                pid=record.pid,
                confidence=record.confidence,
            )
        known_ids = set(graph.nodes)
        for relationship in relationships:
            if (
                relationship.source_evidence_id not in known_ids
                or relationship.target_evidence_id not in known_ids
            ):
                continue
            graph.add_edge(
                relationship.source_evidence_id,
                relationship.target_evidence_id,
                relationship_id=relationship.relationship_id,
                relationship_type=relationship.relationship_type,
                reason=relationship.reason,
                source_plugin=relationship.source_plugin,
                matched_fields=relationship.matched_fields,
                confidence=relationship.confidence,
            )
        return graph

    @staticmethod
    def to_payload(
        graph: nx.DiGraph,
        *,
        node_limit: int | None = 500,
        edge_limit: int | None = 1000,
    ) -> dict:
        """Serialize graph with optional hard limits to protect clients."""
        nodes = []
        for node_id, data in graph.nodes(data=True):
            nodes.append({"id": node_id, **{k: v for k, v in data.items() if k != "id"}})
            if node_limit is not None and len(nodes) >= node_limit:
                break
        allowed = {n["id"] for n in nodes}
        edges = []
        for src, dst, data in graph.edges(data=True):
            if src not in allowed or dst not in allowed:
                continue
            edges.append(
                {
                    "source": src,
                    "target": dst,
                    "relationship_id": data.get("relationship_id"),
                    "relationship_type": data.get("relationship_type"),
                    "reason": data.get("reason"),
                    "source_plugin": data.get("source_plugin"),
                    "matched_fields": data.get("matched_fields") or {},
                    "confidence": data.get("confidence"),
                }
            )
            if edge_limit is not None and len(edges) >= edge_limit:
                break
        return {
            "nodes": nodes,
            "edges": edges,
            "truncated": {
                "node_count": graph.number_of_nodes(),
                "edge_count": graph.number_of_edges(),
                "returned_nodes": len(nodes),
                "returned_edges": len(edges),
                "truncated": graph.number_of_nodes() > len(nodes)
                or graph.number_of_edges() > len(edges),
            },
        }
