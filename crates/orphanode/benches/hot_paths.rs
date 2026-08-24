use std::{fmt::Write as _, hint::black_box, path::Path, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use orphanode::{
    domain::graph::{FileGraph, FileId},
    javascript::parse_file,
};

const STRONGLY_CONNECTED_COMPONENT_SIZE: usize = 8;

fn graph_algorithms(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("file_graph");
    group
        .sample_size(40)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));

    for file_count in [1_024_usize, 16_384] {
        let graph = deterministic_component_graph(file_count);
        let roots = [FileId(0), FileId(file_count / 2)];
        let included = vec![true; file_count];
        let element_count = u64::try_from(file_count).expect("benchmark size fits in u64");
        group.throughput(Throughput::Elements(element_count));

        group.bench_with_input(
            BenchmarkId::new("reachable_from_many", file_count),
            &file_count,
            |bencher, _| {
                bencher.iter(|| {
                    let reachable = black_box(&graph).reachable_from_many(black_box(&roots));
                    black_box(reachable)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("strongly_connected_components", file_count),
            &file_count,
            |bencher, _| {
                bencher.iter(|| {
                    let components = black_box(&graph).components_within(black_box(&included));
                    black_box(components)
                });
            },
        );
    }

    group.finish();
}

fn parser_fact_extraction(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("parser_fact_extraction");
    group
        .sample_size(30)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    let physical_path = Path::new("benchmark.ts");

    for binding_count in [64_usize, 512] {
        let source = deterministic_typescript_source(binding_count);
        assert_typescript_fixture_parses(physical_path, &source);
        let byte_count = u64::try_from(source.len()).expect("benchmark source fits in u64");
        group.throughput(Throughput::Bytes(byte_count));

        group.bench_with_input(
            BenchmarkId::new("typescript_bindings", binding_count),
            &binding_count,
            |bencher, _| {
                bencher.iter(|| {
                    black_box(parse_file(
                        black_box("benchmark.ts"),
                        black_box(physical_path),
                        black_box(source.as_str()),
                    ))
                });
            },
        );
    }

    group.finish();
}

fn assert_typescript_fixture_parses(physical_path: &Path, source: &str) {
    let facts = parse_file("benchmark.ts", physical_path, source);
    assert!(
        facts.diagnostics.is_empty(),
        "benchmark fixture must parse without diagnostics"
    );
}

fn deterministic_component_graph(file_count: usize) -> FileGraph {
    assert_eq!(file_count % STRONGLY_CONNECTED_COMPONENT_SIZE, 0);
    let mut graph = FileGraph::new(file_count);

    for component_start in (0..file_count).step_by(STRONGLY_CONNECTED_COMPONENT_SIZE) {
        for offset in 0..STRONGLY_CONNECTED_COMPONENT_SIZE {
            let source = component_start + offset;
            let target = component_start + (offset + 1) % STRONGLY_CONNECTED_COMPONENT_SIZE;
            graph.add_edge(FileId(source), FileId(target));
        }
        let next_component = component_start + STRONGLY_CONNECTED_COMPONENT_SIZE;
        if next_component < file_count {
            graph.add_edge(FileId(component_start), FileId(next_component));
        }
    }

    graph.finish();
    graph
}

fn deterministic_typescript_source(binding_count: usize) -> String {
    let mut source = String::with_capacity(binding_count.saturating_mul(160));
    for index in 0..binding_count {
        writeln!(
            source,
            "import {{ dependency{index} }} from \"./dependency-{index}.js\";"
        )
        .expect("writing to a String cannot fail");
        writeln!(
            source,
            "export const value{index}: number = dependency{index} + {index};"
        )
        .expect("writing to a String cannot fail");
    }

    source.push_str("export class Registry {\n");
    for index in 0..binding_count / 8 {
        writeln!(
            source,
            "  method{index}(input: number): number {{ return input + value{}; }}",
            index * 8
        )
        .expect("writing to a String cannot fail");
    }
    source.push_str("}\n");
    source
}

criterion_group!(benches, graph_algorithms, parser_fact_extraction);
criterion_main!(benches);
