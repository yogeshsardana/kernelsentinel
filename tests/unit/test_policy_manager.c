#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "include/kernelsentinel.h"
#include "include/ks_policy.h"
#include "include/ks_errors.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { printf("PASSED\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); tests_failed++; } while(0)

void test_policy_init_destroy(void)
{
    TEST("policy context init and destroy");
    ks_policy_context_t *ctx = NULL;
    ks_error_t err = ks_policy_init(&ctx);
    if (err != KS_SUCCESS) { FAIL("init failed"); return; }
    if (!ctx) { FAIL("ctx is NULL"); return; }
    ks_policy_destroy(ctx);
    PASS();
}

void test_policy_evaluate(void)
{
    TEST("policy evaluate allow");

    ks_policy_context_t *ctx = NULL;
    ks_error_t err = ks_policy_init(&ctx);
    if (err != KS_SUCCESS) { FAIL("init failed"); return; }

    ks_event_t event = {0};
    event.event_type = KS_EVENT_FILE_OPEN;
    event.pid = 100;
    event.timestamp_ns = 0;

    ks_action_t action = KS_ACTION_DENY;
    err = ks_policy_evaluate(ctx, &event, &action);
    if (err != KS_SUCCESS) { FAIL("evaluate failed"); ks_policy_destroy(ctx); return; }

    ks_policy_destroy(ctx);
    PASS();
}

void test_policy_load_file(void)
{
    TEST("policy load file - not found");
    ks_policy_context_t *ctx = NULL;
    ks_policy_init(&ctx);

    ks_error_t err = ks_policy_load_file(ctx, "/nonexistent/policy.yaml");
    if (err == KS_SUCCESS) { FAIL("should have failed"); ks_policy_destroy(ctx); return; }

    ks_policy_destroy(ctx);
    PASS();
}

void test_policy_stats(void)
{
    TEST("policy get stats");
    ks_policy_context_t *ctx = NULL;
    ks_policy_init(&ctx);

    ks_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    ks_error_t err = ks_policy_get_stats(ctx, &stats);
    if (err != KS_SUCCESS) { FAIL("get_stats failed"); ks_policy_destroy(ctx); return; }

    ks_policy_destroy(ctx);
    PASS();
}

void test_policy_version_check(void)
{
    TEST("policy version check");
    ks_policy_header_t header;
    memset(&header, 0, sizeof(header));
    header.policy_version = 1;

    ks_error_t err = ks_policy_check_version(&header, 1);
    if (err != KS_SUCCESS) { FAIL("version 1 should match min 1"); return; }

    err = ks_policy_check_version(&header, 2);
    if (err != KS_ERR_POLICY_VERSION) { FAIL("version 1 should be < min 2"); return; }

    PASS();
}

void test_attestation_compare(void)
{
    TEST("attestation compare");
    ks_attestation_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    a.pcr_index = 15;
    b.pcr_index = 15;
    assert(ks_attestation_compare(&a, &b) == 0);

    b.pcr_index = 16;
    assert(ks_attestation_compare(&a, &b) != 0);

    PASS();
}

int main(void)
{
    printf("KernelSentinel Unit Tests\n");
    printf("=========================\n\n");

    test_policy_init_destroy();
    test_policy_evaluate();
    test_policy_load_file();
    test_policy_stats();
    test_policy_version_check();
    test_attestation_compare();

    printf("\nResults: %d passed, %d failed out of %d\n",
           tests_passed, tests_failed, tests_passed + tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
