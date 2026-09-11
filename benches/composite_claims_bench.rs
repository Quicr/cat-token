// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::claims::{
    CatToken, CompositeClaim, CompositeClaims, CompositeOperator, composite_utils,
};
use cat_token::token::CatTokenValidator;
use chrono::{Duration, Utc};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn create_valid_token(issuer: &str) -> CatToken {
    let exp = Utc::now() + Duration::hours(1);

    CatToken::new()
        .with_issuer(issuer)
        .with_audience(vec!["benchmark-audience".to_string()])
        .with_expiration(exp)
        .with_cwt_id("benchmark-id")
}

fn create_expired_token(issuer: &str) -> CatToken {
    let exp = Utc::now() - Duration::hours(1);

    CatToken::new()
        .with_issuer(issuer)
        .with_audience(vec!["benchmark-audience".to_string()])
        .with_expiration(exp)
        .with_cwt_id("expired-id")
}

fn bench_or_composite_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("or_composite_evaluation");

    for token_count in [1, 10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("tokens", token_count),
            token_count,
            |b, &token_count| {
                let validator = CatTokenValidator::dangerously_any_issuer();
                let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
                    validator
                        .validate(token)
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
                };

                let tokens: Vec<CatToken> = (0..token_count)
                    .map(|i| create_valid_token(&format!("issuer{}", i)))
                    .collect();

                let or_composite = composite_utils::create_or_from_tokens(tokens);

                b.iter(|| {
                    let result = or_composite.evaluate(black_box(&validator_fn));
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

fn bench_and_composite_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("and_composite_evaluation");

    for token_count in [1, 10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("tokens", token_count),
            token_count,
            |b, &token_count| {
                let validator = CatTokenValidator::dangerously_any_issuer();
                let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
                    validator
                        .validate(token)
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
                };

                let tokens: Vec<CatToken> = (0..token_count)
                    .map(|i| create_valid_token(&format!("issuer{}", i)))
                    .collect();

                let and_composite = composite_utils::create_and_from_tokens(tokens);

                b.iter(|| {
                    let result = and_composite.evaluate(black_box(&validator_fn));
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

fn bench_nor_composite_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("nor_composite_evaluation");

    for token_count in [1, 10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("tokens", token_count),
            token_count,
            |b, &token_count| {
                let validator = CatTokenValidator::dangerously_any_issuer();
                let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
                    validator
                        .validate(token)
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
                };

                // Create expired tokens for NOR to succeed
                let tokens: Vec<CatToken> = (0..token_count)
                    .map(|i| create_expired_token(&format!("issuer{}", i)))
                    .collect();

                let nor_composite = composite_utils::create_nor_from_tokens(tokens);

                b.iter(|| {
                    let result = nor_composite.evaluate(black_box(&validator_fn));
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

fn bench_nested_composite_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("nested_composite_evaluation");

    for depth in [1, 2, 3, 4, 5].iter() {
        group.bench_with_input(BenchmarkId::new("depth", depth), depth, |b, &depth| {
            let validator = CatTokenValidator::dangerously_any_issuer();
            let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
                validator
                    .validate(token)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            };

            // Create nested structure with specified depth
            let token = create_valid_token("base-issuer");
            let mut composite = composite_utils::create_or_from_tokens(vec![token]);

            for _ in 1..depth {
                let mut new_composite = CompositeClaim::new(CompositeOperator::Or);
                new_composite.add_composite(composite);
                composite = new_composite;
            }

            b.iter(|| {
                let result = composite.evaluate(black_box(&validator_fn));
                black_box(result);
            });
        });
    }

    group.finish();
}

fn bench_composite_depth_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("composite_depth_calculation");

    for depth in [1, 2, 3, 4, 5, 8, 10].iter() {
        group.bench_with_input(BenchmarkId::new("depth", depth), depth, |b, &depth| {
            // Create nested structure with specified depth
            let token = create_valid_token("base-issuer");
            let mut composite = composite_utils::create_or_from_tokens(vec![token]);

            for _ in 1..depth {
                let mut new_composite = CompositeClaim::new(CompositeOperator::Or);
                new_composite.add_composite(composite);
                composite = new_composite;
            }

            b.iter(|| {
                let depth = composite.get_depth();
                black_box(depth);
            });
        });
    }

    group.finish();
}

fn bench_token_validation_with_composite(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_validation_with_composite");

    for token_count in [1, 5, 10, 25, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("composite_tokens", token_count),
            token_count,
            |b, &token_count| {
                let validator = CatTokenValidator::dangerously_any_issuer();

                let tokens: Vec<CatToken> = (0..token_count)
                    .map(|i| create_valid_token(&format!("issuer{}", i)))
                    .collect();

                let or_composite = composite_utils::create_or_from_tokens(tokens);
                let token_with_composite =
                    create_valid_token("main-issuer").with_or_composite(or_composite);

                b.iter(|| {
                    let result = validator.validate(black_box(&token_with_composite));
                    let _ = black_box(result);
                });
            },
        );
    }

    group.finish();
}

fn bench_composite_claims_container(c: &mut Criterion) {
    c.bench_function("composite_claims_container", |b| {
        let validator = CatTokenValidator::dangerously_any_issuer();
        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        let mut container = CompositeClaims::default();
        container.or_claim = Some(composite_utils::create_or_from_tokens(vec![
            create_valid_token("issuer1"),
        ]));
        container.and_claim = Some(composite_utils::create_and_from_tokens(vec![
            create_valid_token("issuer2"),
            create_valid_token("issuer3"),
        ]));

        b.iter(|| {
            let has_composites = container.has_composites();
            let validation_result = container.validate_all(black_box(&validator_fn));
            black_box(has_composites);
            let _ = black_box(validation_result);
        });
    });
}

fn bench_composite_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("composite_creation");

    for token_count in [1, 10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("tokens", token_count),
            token_count,
            |b, &token_count| {
                let tokens: Vec<CatToken> = (0..token_count)
                    .map(|i| create_valid_token(&format!("issuer{}", i)))
                    .collect();

                b.iter(|| {
                    let or_composite =
                        composite_utils::create_or_from_tokens(black_box(tokens.clone()));
                    black_box(or_composite);
                });
            },
        );
    }

    group.finish();
}

fn bench_claim_set_operations(c: &mut Criterion) {
    c.bench_function("claim_set_operations", |b| {
        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");
        let composite = composite_utils::create_or_from_tokens(vec![token1, token2]);

        b.iter(|| {
            let mut claim_composite = CompositeClaim::new(CompositeOperator::And);
            claim_composite.add_token(black_box(create_valid_token("test")));
            claim_composite.add_composite(black_box(composite.clone()));
            black_box(claim_composite);
        });
    });
}

criterion_group!(
    benches,
    bench_or_composite_evaluation,
    bench_and_composite_evaluation,
    bench_nor_composite_evaluation,
    bench_nested_composite_evaluation,
    bench_composite_depth_calculation,
    bench_token_validation_with_composite,
    bench_composite_claims_container,
    bench_composite_creation,
    bench_claim_set_operations
);

criterion_main!(benches);
