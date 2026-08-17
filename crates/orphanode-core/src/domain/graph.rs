use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileGraph {
    outgoing: Vec<Vec<FileId>>,
}

impl FileGraph {
    #[must_use]
    pub fn new(file_count: usize) -> Self {
        Self {
            outgoing: vec![Vec::new(); file_count],
        }
    }

    pub fn add_edge(&mut self, from: FileId, to: FileId) {
        self.outgoing[from.0].push(to);
    }

    pub fn finish(&mut self) {
        for targets in &mut self.outgoing {
            targets.sort_unstable();
            targets.dedup();
        }
    }

    #[must_use]
    pub fn reachable_from(&self, root: FileId) -> Vec<bool> {
        self.reachable_from_many(&[root])
    }

    #[must_use]
    pub fn reachable_from_many(&self, roots: &[FileId]) -> Vec<bool> {
        let mut reachable = vec![false; self.outgoing.len()];
        let mut queue = VecDeque::new();
        for root in roots {
            if !reachable[root.0] {
                reachable[root.0] = true;
                queue.push_back(*root);
            }
        }

        while let Some(file) = queue.pop_front() {
            for target in &self.outgoing[file.0] {
                if !reachable[target.0] {
                    reachable[target.0] = true;
                    queue.push_back(*target);
                }
            }
        }

        reachable
    }

    #[must_use]
    pub fn components_within(&self, included: &[bool]) -> Vec<Vec<FileId>> {
        debug_assert_eq!(self.outgoing.len(), included.len());

        let finishing_order = self.finishing_order(included);
        let reversed = self.reversed();
        let mut assigned = vec![false; self.outgoing.len()];
        let mut components = Vec::new();

        for start in finishing_order.into_iter().rev() {
            if assigned[start.0] || !included[start.0] {
                continue;
            }

            let mut component = Vec::new();
            let mut stack = vec![start];
            assigned[start.0] = true;

            while let Some(file) = stack.pop() {
                component.push(file);
                for source in &reversed[file.0] {
                    if included[source.0] && !assigned[source.0] {
                        assigned[source.0] = true;
                        stack.push(*source);
                    }
                }
            }

            component.sort_unstable();
            components.push(component);
        }

        components.sort_by_key(|component| component[0]);
        components
    }

    fn finishing_order(&self, included: &[bool]) -> Vec<FileId> {
        let mut visited = vec![false; self.outgoing.len()];
        let mut order = Vec::new();

        for start_index in 0..self.outgoing.len() {
            if !included[start_index] || visited[start_index] {
                continue;
            }

            let start = FileId(start_index);
            visited[start_index] = true;
            let mut stack = vec![(start, 0_usize)];

            while let Some((file, next_edge)) = stack.last_mut() {
                let targets = &self.outgoing[file.0];
                if *next_edge < targets.len() {
                    let target = targets[*next_edge];
                    *next_edge += 1;
                    if included[target.0] && !visited[target.0] {
                        visited[target.0] = true;
                        stack.push((target, 0));
                    }
                } else {
                    order.push(*file);
                    stack.pop();
                }
            }
        }

        order
    }

    fn reversed(&self) -> Vec<Vec<FileId>> {
        let mut reversed = vec![Vec::new(); self.outgoing.len()];
        for (source, targets) in self.outgoing.iter().enumerate() {
            for target in targets {
                reversed[target.0].push(FileId(source));
            }
        }
        for sources in &mut reversed {
            sources.sort_unstable();
        }
        reversed
    }
}

#[cfg(test)]
mod tests {
    use super::{FileGraph, FileId};

    struct DeterministicRandom(u64);

    impl DeterministicRandom {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
    }

    #[test]
    fn reachability_does_not_activate_a_disconnected_cycle() {
        let mut graph = FileGraph::new(4);
        graph.add_edge(FileId(0), FileId(1));
        graph.add_edge(FileId(2), FileId(3));
        graph.add_edge(FileId(3), FileId(2));
        graph.finish();

        assert_eq!(
            graph.reachable_from(FileId(0)),
            vec![true, true, false, false]
        );
    }

    #[test]
    fn components_are_stable_and_group_cycles() {
        let mut graph = FileGraph::new(5);
        graph.add_edge(FileId(0), FileId(1));
        graph.add_edge(FileId(1), FileId(0));
        graph.add_edge(FileId(3), FileId(4));
        graph.finish();

        let components = graph.components_within(&[true, true, true, true, true]);

        assert_eq!(
            components,
            vec![
                vec![FileId(0), FileId(1)],
                vec![FileId(2)],
                vec![FileId(3)],
                vec![FileId(4)],
            ]
        );
    }

    #[test]
    fn reachability_accepts_multiple_roots() {
        let mut graph = FileGraph::new(5);
        graph.add_edge(FileId(0), FileId(1));
        graph.add_edge(FileId(3), FileId(4));
        graph.finish();

        assert_eq!(
            graph.reachable_from_many(&[FileId(3), FileId(0)]),
            vec![true, true, false, true, true]
        );
    }

    #[test]
    fn generated_graphs_match_reference_reachability_and_components() {
        for seed in 0_u64..64 {
            for file_count in 1..=12 {
                let mut random = DeterministicRandom(seed ^ file_count as u64);
                let mut graph = FileGraph::new(file_count);
                let mut adjacency = vec![Vec::new(); file_count];
                for (source, targets) in adjacency.iter_mut().enumerate() {
                    for target in 0..file_count {
                        if random.next().is_multiple_of(4) {
                            graph.add_edge(FileId(source), FileId(target));
                            targets.push(target);
                        }
                    }
                }
                graph.finish();

                let roots = (0..file_count)
                    .filter(|_| random.next().is_multiple_of(3))
                    .map(FileId)
                    .collect::<Vec<_>>();
                assert_eq!(
                    graph.reachable_from_many(&roots),
                    reference_reachable(&adjacency, &roots, &vec![true; file_count]),
                    "reachability mismatch for seed {seed} with {file_count} files"
                );

                let included = (0..file_count)
                    .map(|_| !random.next().is_multiple_of(4))
                    .collect::<Vec<_>>();
                assert_eq!(
                    graph.components_within(&included),
                    reference_components(&adjacency, &included),
                    "component mismatch for seed {seed} with {file_count} files"
                );
            }
        }
    }

    fn reference_reachable(
        adjacency: &[Vec<usize>],
        roots: &[FileId],
        included: &[bool],
    ) -> Vec<bool> {
        let mut reachable = vec![false; adjacency.len()];
        for root in roots {
            if included[root.0] {
                reachable[root.0] = true;
            }
        }
        loop {
            let mut changed = false;
            for (source, targets) in adjacency.iter().enumerate() {
                if !reachable[source] {
                    continue;
                }
                for &target in targets {
                    if included[target] && !reachable[target] {
                        reachable[target] = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                return reachable;
            }
        }
    }

    fn reference_components(adjacency: &[Vec<usize>], included: &[bool]) -> Vec<Vec<FileId>> {
        let mut assigned = vec![false; adjacency.len()];
        let mut components = Vec::new();
        for (source, &source_included) in included.iter().enumerate() {
            if !source_included || assigned[source] {
                continue;
            }
            let forward = reference_reachable(adjacency, &[FileId(source)], included);
            let mut component = Vec::new();
            for (target, &target_included) in included.iter().enumerate() {
                if !target_included || !forward[target] {
                    continue;
                }
                let backward = reference_reachable(adjacency, &[FileId(target)], included);
                if backward[source] {
                    assigned[target] = true;
                    component.push(FileId(target));
                }
            }
            components.push(component);
        }
        components.sort_by_key(|component| component[0]);
        components
    }
}
