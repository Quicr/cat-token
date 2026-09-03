// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::CatError;
use cat_token::claims::{
    CatToken, ClaimSet, CompositeClaim, CompositeClaims, CompositeOperator, composite_utils,
};
use cat_token::token::CatTokenValidator;
use chrono::{Duration, Utc};

fn create_valid_token(issuer: &str) -> CatToken {
    let exp = Utc::now() + Duration::hours(1);

    CatToken::new()
        .with_issuer(issuer)
        .with_audience(vec!["test-audience".to_string()])
        .with_expiration(exp)
        .with_cwt_id_str("test-id")
}

fn create_expired_token() -> CatToken {
    let exp = Utc::now() - Duration::hours(1);

    CatToken::new()
        .with_issuer("test-issuer")
        .with_audience(vec!["test-audience".to_string()])
        .with_expiration(exp)
        .with_cwt_id_str("expired-id")
}

#[cfg(test)]
mod composite_claims_tests {
    use super::*;

    #[test]
    fn test_create_or_composite() {
        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");

        let or_composite = composite_utils::create_or_from_tokens(vec![token1, token2]);

        assert_eq!(or_composite.op, CompositeOperator::Or);
        assert_eq!(or_composite.claims.len(), 2);
        assert_eq!(or_composite.get_depth(), 1);
    }

    #[test]
    fn test_create_nor_composite() {
        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");

        let nor_composite = composite_utils::create_nor_from_tokens(vec![token1, token2]);

        assert_eq!(nor_composite.op, CompositeOperator::Nor);
        assert_eq!(nor_composite.claims.len(), 2);
        assert_eq!(nor_composite.get_depth(), 1);
    }

    #[test]
    fn test_create_and_composite() {
        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");

        let and_composite = composite_utils::create_and_from_tokens(vec![token1, token2]);

        assert_eq!(and_composite.op, CompositeOperator::And);
        assert_eq!(and_composite.claims.len(), 2);
        assert_eq!(and_composite.get_depth(), 1);
    }

    #[test]
    fn test_or_evaluation_with_valid_tokens() {
        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");

        let or_composite = composite_utils::create_or_from_tokens(vec![token1, token2]);
        let validator = CatTokenValidator::new();

        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // OR should succeed when at least one token is valid
        assert!(or_composite.evaluate(&validator_fn));
    }

    #[test]
    fn test_or_evaluation_with_some_invalid_tokens() {
        let valid_token = create_valid_token("valid-issuer");
        let expired_token = create_expired_token();

        let or_composite = composite_utils::create_or_from_tokens(vec![valid_token, expired_token]);
        let validator = CatTokenValidator::new();

        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // OR should succeed when at least one token is valid
        assert!(or_composite.evaluate(&validator_fn));
    }

    #[test]
    fn test_or_evaluation_with_all_invalid_tokens() {
        let expired_token1 = create_expired_token();
        let expired_token2 = create_expired_token();

        let or_composite =
            composite_utils::create_or_from_tokens(vec![expired_token1, expired_token2]);
        let validator = CatTokenValidator::new();

        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // OR should fail when all tokens are invalid
        assert!(!or_composite.evaluate(&validator_fn));
    }

    #[test]
    fn test_nor_evaluation_with_all_invalid_tokens() {
        let expired_token1 = create_expired_token();
        let expired_token2 = create_expired_token();

        let nor_composite =
            composite_utils::create_nor_from_tokens(vec![expired_token1, expired_token2]);
        let validator = CatTokenValidator::new();

        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // NOR should succeed when all tokens are invalid
        assert!(nor_composite.evaluate(&validator_fn));
    }

    #[test]
    fn test_nor_evaluation_with_some_valid_tokens() {
        let valid_token = create_valid_token("valid-issuer");
        let expired_token = create_expired_token();

        let nor_composite =
            composite_utils::create_nor_from_tokens(vec![valid_token, expired_token]);
        let validator = CatTokenValidator::new();

        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // NOR should fail when any token is valid
        assert!(!nor_composite.evaluate(&validator_fn));
    }

    #[test]
    fn test_and_evaluation_with_all_valid_tokens() {
        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");

        let and_composite = composite_utils::create_and_from_tokens(vec![token1, token2]);
        let validator = CatTokenValidator::new();

        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // AND should succeed when all tokens are valid
        assert!(and_composite.evaluate(&validator_fn));
    }

    #[test]
    fn test_and_evaluation_with_some_invalid_tokens() {
        let valid_token = create_valid_token("valid-issuer");
        let expired_token = create_expired_token();

        let and_composite =
            composite_utils::create_and_from_tokens(vec![valid_token, expired_token]);
        let validator = CatTokenValidator::new();

        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // AND should fail when any token is invalid
        assert!(!and_composite.evaluate(&validator_fn));
    }

    #[test]
    fn test_nested_composite_depth() {
        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");
        let token3 = create_valid_token("issuer3");

        // Create nested structure: OR(token1, AND(token2, token3))
        let inner_and = composite_utils::create_and_from_tokens(vec![token2, token3]);
        let mut outer_or = CompositeClaim::new(CompositeOperator::Or);
        outer_or.add_token(token1);
        outer_or.add_composite(inner_and);

        assert_eq!(outer_or.get_depth(), 2);
    }

    #[test]
    fn test_nested_composite_evaluation() {
        let valid_token1 = create_valid_token("issuer1");
        let valid_token2 = create_valid_token("issuer2");
        let expired_token = create_expired_token();

        // Create nested structure: OR(validToken1, AND(validToken2, expiredToken))
        let inner_and = composite_utils::create_and_from_tokens(vec![valid_token2, expired_token]);
        let mut outer_or = CompositeClaim::new(CompositeOperator::Or);
        outer_or.add_token(valid_token1);
        outer_or.add_composite(inner_and);

        let validator = CatTokenValidator::new();
        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // Should succeed because OR has one valid path (validToken1)
        assert!(outer_or.evaluate(&validator_fn));
    }

    #[test]
    fn test_token_with_composite_claims_validation() {
        let valid_token1 = create_valid_token("issuer1");
        let valid_token2 = create_valid_token("issuer2");

        let or_composite = composite_utils::create_or_from_tokens(vec![valid_token1, valid_token2]);

        let token_with_composite =
            create_valid_token("main-issuer").with_or_composite(or_composite);

        let validator = CatTokenValidator::new();

        // Main token validation should include composite claims validation
        assert!(validator.validate(&token_with_composite).is_ok());
    }

    #[test]
    fn test_token_with_failing_composite_claims_validation() {
        let expired_token1 = create_expired_token();
        let expired_token2 = create_expired_token();

        let and_composite =
            composite_utils::create_and_from_tokens(vec![expired_token1, expired_token2]);

        let token_with_composite =
            create_valid_token("main-issuer").with_and_composite(and_composite);

        let validator = CatTokenValidator::new();

        // Should fail because composite claims validation fails
        match validator.validate(&token_with_composite) {
            Err(CatError::InvalidClaimValue(_)) => {} // Expected
            other => panic!("Expected InvalidClaimValue error, got: {:?}", other),
        }
    }

    #[test]
    fn test_deep_nesting_depth_check() {
        let token = create_valid_token("issuer");

        // Create deeply nested structure
        let mut composite = CompositeClaim::new(CompositeOperator::Or);
        composite.add_token(token);

        for _ in 0..15 {
            // Create nesting deeper than MAX_NESTING_DEPTH
            let mut new_composite = CompositeClaim::new(CompositeOperator::Or);
            new_composite.add_composite(composite);
            composite = new_composite;
        }

        let token_with_deep_composite =
            create_valid_token("main-issuer").with_or_composite(composite);

        let validator = CatTokenValidator::new();

        // Should fail due to excessive nesting depth
        match validator.validate(&token_with_deep_composite) {
            Err(CatError::InvalidClaimValue(_)) => {} // Expected
            other => panic!("Expected InvalidClaimValue error, got: {:?}", other),
        }
    }

    #[test]
    fn test_composite_claims_container_methods() {
        let mut container = CompositeClaims::default();

        assert!(!container.has_composites());

        let or_composite = composite_utils::create_or_from_tokens(vec![create_valid_token("test")]);
        container.or_claim = Some(or_composite);

        assert!(container.has_composites());

        let validator = CatTokenValidator::new();
        let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
            validator
                .validate(token)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };

        // Test validation passes with valid composite
        assert!(container.validate_all(&validator_fn).is_ok());
    }

    #[test]
    fn test_claim_set_with_token() {
        let token = create_valid_token("test-issuer");
        let claim_set = ClaimSet::Token(Box::new(token));

        match claim_set {
            ClaimSet::Token(boxed_token) => {
                assert_eq!(boxed_token.core.iss, Some("test-issuer".to_string()));
            }
            _ => panic!("Expected ClaimSet::Token"),
        }
    }

    #[test]
    fn test_claim_set_with_composite() {
        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");

        let composite = composite_utils::create_or_from_tokens(vec![token1, token2]);
        let claim_set = ClaimSet::Composite(Box::new(composite));

        match claim_set {
            ClaimSet::Composite(boxed_composite) => {
                assert_eq!(boxed_composite.op, CompositeOperator::Or);
                assert_eq!(boxed_composite.claims.len(), 2);
            }
            _ => panic!("Expected ClaimSet::Composite"),
        }
    }

    #[test]
    fn test_composite_claim_builder_methods() {
        let mut composite = CompositeClaim::new(CompositeOperator::And);

        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");
        let nested_composite = composite_utils::create_or_from_tokens(vec![token1.clone()]);

        composite.add_token(token1);
        composite.add_token(token2);
        composite.add_composite(nested_composite);

        assert_eq!(composite.claims.len(), 3);
        assert_eq!(composite.get_depth(), 2); // Due to nested composite
    }

    #[test]
    fn test_max_depth_calculation() {
        let mut container = CompositeClaims::default();

        // Add composites with different depths
        let shallow_composite =
            composite_utils::create_or_from_tokens(vec![create_valid_token("test")]);
        container.or_claim = Some(shallow_composite);

        let token1 = create_valid_token("issuer1");
        let token2 = create_valid_token("issuer2");
        let inner_composite = composite_utils::create_and_from_tokens(vec![token1, token2]);
        let mut deeper_composite = CompositeClaim::new(CompositeOperator::Or);
        deeper_composite.add_composite(inner_composite);
        container.and_claim = Some(deeper_composite);

        assert_eq!(container.get_max_depth(), 2);
    }
}
