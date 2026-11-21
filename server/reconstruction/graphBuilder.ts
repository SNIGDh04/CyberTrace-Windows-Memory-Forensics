import { entityLabel } from "../evidence/normalizer.ts";
import type { EvidenceRecord, RelationshipRecord } from "../types.ts";

export interface GraphNode {
  id: string;
  evidence_id: string;
  type: EvidenceRecord["type"];
  label: string;
  source_plugin: string;
  pid: string | null;
  confidence: EvidenceRecord["confidence"];
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship_id: string;
  relationship_type: RelationshipRecord["relationship_type"];
  reason: string;
  source_plugin: string;
  matched_fields: Record<string, unknown>;
  confidence: RelationshipRecord["confidence"];
}

export interface BuiltGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export class EvidenceGraphBuilder {
  static build(
    evidence: EvidenceRecord[],
    relationships: RelationshipRecord[]
  ): BuiltGraph {
    const nodeMap = new Map<string, GraphNode>();
    for (const record of evidence) {
      nodeMap.set(record.evidence_id, {
        id: record.evidence_id,
        evidence_id: record.evidence_id,
        type: record.type,
        label: entityLabel(record),
        source_plugin: record.source_plugin,
        pid: record.pid,
        confidence: record.confidence,
      });
    }

    const edges: GraphEdge[] = [];
    for (const rel of relationships) {
      if (!nodeMap.has(rel.source_evidence_id) || !nodeMap.has(rel.target_evidence_id)) {
        continue;
      }
      edges.push({
        source: rel.source_evidence_id,
        target: rel.target_evidence_id,
        relationship_id: rel.relationship_id,
        relationship_type: rel.relationship_type,
        reason: rel.reason,
        source_plugin: rel.source_plugin,
        matched_fields: rel.matched_fields || {},
        confidence: rel.confidence,
      });
    }

    return { nodes: [...nodeMap.values()], edges };
  }

  static toPayload(
    graph: BuiltGraph,
    options: { nodeLimit?: number | null; edgeLimit?: number | null } = {}
  ): {
    nodes: GraphNode[];
    edges: GraphEdge[];
    truncated: {
      node_count: number;
      edge_count: number;
      returned_nodes: number;
      returned_edges: number;
      truncated: boolean;
    };
  } {
    const nodeLimit = options.nodeLimit === undefined ? 500 : options.nodeLimit;
    const edgeLimit = options.edgeLimit === undefined ? 1000 : options.edgeLimit;

    const nodes =
      nodeLimit !== null ? graph.nodes.slice(0, nodeLimit) : [...graph.nodes];
    const allowed = new Set(nodes.map((n) => n.id));
    const filteredEdges = graph.edges.filter(
      (e) => allowed.has(e.source) && allowed.has(e.target)
    );
    const edges =
      edgeLimit !== null ? filteredEdges.slice(0, edgeLimit) : filteredEdges;

    return {
      nodes,
      edges,
      truncated: {
        node_count: graph.nodes.length,
        edge_count: graph.edges.length,
        returned_nodes: nodes.length,
        returned_edges: edges.length,
        truncated:
          graph.nodes.length > nodes.length || graph.edges.length > edges.length,
      },
    };
  }
}
