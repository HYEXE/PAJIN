"""Canonical Graph bindings shared by inert agentic planning components."""

from __future__ import annotations

from pajin.graph.models import GraphHypothesis, GraphRelation, GraphSurface
from pajin.graph.projection import GraphSnapshot


def target_root_hypothesis_pairs(snapshot: GraphSnapshot) -> frozenset[tuple[str, str]]:
    """Return exact Target-to-root bindings admitted through `Surface motivates Hypothesis`."""

    surfaces = {
        node.node_id: node.target_id
        for node in snapshot.projection.nodes
        if isinstance(node, GraphSurface)
    }
    hypotheses = {
        node.node_id
        for node in snapshot.projection.nodes
        if isinstance(node, GraphHypothesis)
    }
    return frozenset(
        (surfaces[edge.source.node_id], edge.target.node_id)
        for edge in snapshot.projection.edges
        if edge.relation is GraphRelation.MOTIVATES
        and edge.source.node_id in surfaces
        and edge.target.node_id in hypotheses
    )
