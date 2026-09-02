// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! GraphQL schema/type introspection tests.
//!
//! These assert the registered query/mutation fields and key input/enum
//! types stay present in the schema; they run via async-graphql
//! introspection without a live `AppState`.

use async_graphql::{EmptySubscription, Schema};

use crate::server::graphql::{MutationRoot, QueryRoot};

/// Helper to get all mutation field names from schema introspection
async fn get_mutation_fields() -> String {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute("{ __schema { mutationType { fields { name } } } }")
        .await;
    assert!(
        res.errors.is_empty(),
        "Introspection returned errors: {:?}",
        res.errors
    );
    format!("{}", res.data)
}

/// Helper to get all query field names from schema introspection
async fn get_query_fields() -> String {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute("{ __schema { queryType { fields { name } } } }")
        .await;
    assert!(
        res.errors.is_empty(),
        "Introspection returned errors: {:?}",
        res.errors
    );
    format!("{}", res.data)
}

// === Mutation introspection tests ===

#[tokio::test]
async fn test_add_rules_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("addRules"),
        "Expected mutation 'addRules' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_delete_rules_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("deleteRules"),
        "Expected mutation 'deleteRules' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_attach_ingress_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("attachIngress"),
        "Expected mutation 'attachIngress' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_detach_ingress_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("detachIngress"),
        "Expected mutation 'detachIngress' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_attach_tc_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("attachTc"),
        "Expected mutation 'attachTc' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_detach_tc_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("detachTc"),
        "Expected mutation 'detachTc' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_detach_all_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("detachAll"),
        "Expected mutation 'detachAll' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_add_rule_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("addRule"),
        "Expected mutation 'addRule' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_delete_rule_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("deleteRule"),
        "Expected mutation 'deleteRule' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_flush_rules_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("flushRules"),
        "Expected mutation 'flushRules' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_set_default_action_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("setDefaultAction"),
        "Expected mutation 'setDefaultAction' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_register_tail_call_field_registered() {
    let body = get_mutation_fields().await;
    assert!(
        body.contains("registerTailCall"),
        "Expected mutation 'registerTailCall' in schema: {}",
        body
    );
}

#[tokio::test]
async fn test_clear_stats_mutations_registered() {
    let body = get_mutation_fields().await;
    for field in &[
        "clearGlobalStats",
        "clearRuleStats",
        "clearAllRuleStats",
        "clearEthertypeStats",
        "clearInterfaceStats",
        "clearAllStats",
    ] {
        assert!(
            body.contains(field),
            "Expected mutation '{}' in schema: {}",
            field,
            body
        );
    }
}

// === Query introspection tests ===

#[tokio::test]
async fn test_query_fields_registered() {
    let body = get_query_fields().await;
    for field in &[
        "status",
        "interfaces",
        "stats",
        "ethertypeStats",
        "ruleStats",
        "rules",
    ] {
        assert!(
            body.contains(field),
            "Expected query '{}' in schema: {}",
            field,
            body
        );
    }
}

// === Type introspection tests ===

#[tokio::test]
async fn test_gql_direction_enum_in_schema() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(r#"{ __type(name: "GqlDirection") { kind enumValues { name } } }"#)
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    assert!(
        body.contains("ENUM"),
        "GqlDirection should be an ENUM type: {}",
        body
    );
    assert!(
        body.contains("INGRESS"),
        "GqlDirection should have INGRESS: {}",
        body
    );
    assert!(
        body.contains("EGRESS"),
        "GqlDirection should have EGRESS: {}",
        body
    );
}

#[tokio::test]
async fn test_flow_verdict_list_accepts_limit_arg() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(r#"{ __type(name: "QueryRoot") { fields { name args { name } } } }"#)
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);
    let body = format!("{}", res.data);
    // flowVerdictList must expose both `direction` and the `limit` argument so
    // the CLI and controller can cap the result set.
    assert!(
        body.contains("flowVerdictList"),
        "schema should expose flowVerdictList: {}",
        body
    );
    assert!(
        body.contains("limit"),
        "flowVerdictList should accept a limit arg: {}",
        body
    );
}

#[tokio::test]
async fn test_gql_policy_action_enum_in_schema() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(r#"{ __type(name: "GqlPolicyAction") { kind enumValues { name } } }"#)
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    assert!(body.contains("PASS"), "Should have PASS: {}", body);
    assert!(body.contains("DROP"), "Should have DROP: {}", body);
    assert!(body.contains("LOG"), "Should have LOG: {}", body);
    assert!(
        body.contains("TAIL_CALL"),
        "Should have TAIL_CALL: {}",
        body
    );
}

#[tokio::test]
async fn test_add_rule_input_has_direction_field() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(
            r#"{ __type(name: "AddRuleInput") { inputFields { name type { name kind ofType { name } } } } }"#,
        )
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    assert!(
        body.contains("direction"),
        "AddRuleInput should have 'direction' field: {}",
        body
    );
}

#[tokio::test]
async fn test_delete_rule_input_has_direction_field() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(r#"{ __type(name: "DeleteRuleInput") { inputFields { name } } }"#)
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    assert!(
        body.contains("direction"),
        "DeleteRuleInput should have 'direction' field: {}",
        body
    );
}

#[tokio::test]
async fn test_default_action_input_has_direction_field() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(r#"{ __type(name: "DefaultActionInput") { inputFields { name } } }"#)
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    assert!(
        body.contains("direction"),
        "DefaultActionInput should have 'direction' field: {}",
        body
    );
}

#[tokio::test]
async fn test_tail_call_input_has_direction_field() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(r#"{ __type(name: "TailCallInput") { inputFields { name } } }"#)
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    assert!(
        body.contains("direction"),
        "TailCallInput should have 'direction' field: {}",
        body
    );
}

#[tokio::test]
async fn test_attach_tc_input_type_exists() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(r#"{ __type(name: "AttachTcInput") { inputFields { name } } }"#)
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    assert!(
        body.contains("interface"),
        "AttachTcInput should have 'interface' field: {}",
        body
    );
}

#[tokio::test]
async fn test_detach_tc_input_type_exists() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(r#"{ __type(name: "DetachTcInput") { inputFields { name } } }"#)
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    assert!(
        body.contains("interface"),
        "DetachTcInput should have 'interface' field: {}",
        body
    );
}

// === Verify rules query accepts direction argument ===

#[tokio::test]
async fn test_rules_query_has_direction_argument() {
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish();
    let res = schema
        .execute(
            r#"{
                __type(name: "QueryRoot") {
                    fields {
                        name
                        args { name type { name kind ofType { name } } }
                    }
                }
            }"#,
        )
        .await;
    assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);

    let body = format!("{}", res.data);
    // The rules field should accept a direction argument
    assert!(
        body.contains("rules"),
        "QueryRoot should have 'rules' field: {}",
        body
    );
    assert!(
        body.contains("direction"),
        "Query fields should accept 'direction' argument: {}",
        body
    );
}
