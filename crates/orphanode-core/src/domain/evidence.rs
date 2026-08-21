use std::collections::VecDeque;

use serde::Serialize;

use super::ids::EvidenceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Entry,
    Manifest,
    Script,
    Configuration,
    Import,
    Export,
    Symbol,
    Member,
    Package,
    Plugin,
    Retain,
    Blocker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceNode {
    pub id: EvidenceId,
    pub kind: EvidenceKind,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceGraph {
    nodes: Vec<EvidenceNode>,
    outgoing: Vec<Vec<EvidenceId>>,
}

impl EvidenceGraph {
    /// Adds an evidence node and returns its graph-local identifier.
    ///
    /// # Panics
    ///
    /// Panics if the graph contains more nodes than can be represented by an
    /// [`EvidenceId`].
    #[must_use]
    pub fn add_node(
        &mut self,
        kind: EvidenceKind,
        summary: impl Into<String>,
        path: Option<String>,
        span: Option<(u32, u32)>,
    ) -> EvidenceId {
        let id = EvidenceId(
            u32::try_from(self.nodes.len()).expect("evidence graph exceeded u32 capacity"),
        );
        self.nodes.push(EvidenceNode {
            id,
            kind,
            summary: summary.into(),
            path,
            start: span.map(|value| value.0),
            end: span.map(|value| value.1),
        });
        self.outgoing.push(Vec::new());
        id
    }

    /// Adds a directed edge unless it already exists.
    ///
    /// # Panics
    ///
    /// Panics if `source` does not identify a node in this graph.
    pub fn add_edge(&mut self, source: EvidenceId, target: EvidenceId) {
        let edges = self
            .outgoing
            .get_mut(source.index())
            .expect("evidence source must belong to graph");
        if !edges.contains(&target) {
            edges.push(target);
            edges.sort_unstable();
        }
    }

    #[must_use]
    pub fn node(&self, id: EvidenceId) -> Option<&EvidenceNode> {
        self.nodes.get(id.index())
    }

    #[must_use]
    pub fn shortest_path(&self, sources: &[EvidenceId], target: EvidenceId) -> Vec<EvidenceNode> {
        if target.index() >= self.nodes.len() {
            return Vec::new();
        }

        let mut queue = VecDeque::new();
        let mut previous = vec![None; self.nodes.len()];
        let mut seen = vec![false; self.nodes.len()];
        let mut ordered_sources = sources.to_vec();
        ordered_sources.sort_unstable();
        ordered_sources.dedup();
        for source in ordered_sources {
            if source.index() < seen.len() && !seen[source.index()] {
                seen[source.index()] = true;
                queue.push_back(source);
            }
        }

        while let Some(current) = queue.pop_front() {
            if current == target {
                break;
            }
            for next in self.outgoing.get(current.index()).into_iter().flatten() {
                if !seen[next.index()] {
                    seen[next.index()] = true;
                    previous[next.index()] = Some(current);
                    queue.push_back(*next);
                }
            }
        }

        if !seen[target.index()] {
            return Vec::new();
        }
        let mut ids = vec![target];
        let mut current = target;
        while let Some(parent) = previous[current.index()] {
            ids.push(parent);
            current = parent;
        }
        ids.reverse();
        ids.into_iter()
            .filter_map(|id| self.node(id).cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{EvidenceGraph, EvidenceKind};

    #[test]
    fn explanations_choose_a_deterministic_shortest_path() {
        let mut graph = EvidenceGraph::default();
        let root = graph.add_node(EvidenceKind::Entry, "entry", None, None);
        let alternate = graph.add_node(EvidenceKind::Entry, "alternate", None, None);
        let import = graph.add_node(EvidenceKind::Import, "import", None, None);
        let target = graph.add_node(EvidenceKind::Package, "chalk", None, None);
        graph.add_edge(root, import);
        graph.add_edge(import, target);
        graph.add_edge(alternate, target);

        let path = graph.shortest_path(&[root, alternate], target);
        assert_eq!(
            path.iter()
                .map(|node| node.summary.as_str())
                .collect::<Vec<_>>(),
            ["alternate", "chalk"]
        );
    }
}
