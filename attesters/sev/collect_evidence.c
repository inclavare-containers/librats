/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>
#include <string.h>
#include "sev.h"

#define KVM_HC_VM_HANDLE 13

/* The API of retrieve_attestation_evidence_size and retrieve_attestation_evidence
 * is defined in libttrpc.so.
 */
extern uint32_t retrieve_attestation_evidence_size(uint32_t guest_handle);
extern sev_evidence_t *retrieve_attestation_evidence(uint32_t guest_handle, uint32_t evidence_size);

static int do_hypercall(unsigned int p1)
{
	long ret = 0;

	asm volatile("vmmcall" : "=a"(ret) : "a"(p1) : "memory");

	return (int)ret;
}

rats_attester_err_t sev_collect_evidence(rats_attester_ctx_t *ctx, attestation_evidence_t *evidence,
					 uint8_t *hash, uint32_t hash_len)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	/* Get guest firmware handle by KVM_HC_VM_HANDLE hypercall */
	uint32_t guest_handle = do_hypercall(KVM_HC_VM_HANDLE);
	if (guest_handle <= 0) {
		RATS_ERR("failed to get guest handle, invalid guest_handle %d\n", guest_handle);
		return -RATS_ATTESTER_ERR_INVALID;
	}
	RATS_DEBUG("guest firmware handle is %d\n", guest_handle);

	/* Send retrieve_attestation_evidence request to AEB service through vsock.
	 * AEB service returns attestation evidence to sev attester.
	 * The implement of retrieve_attestation_evidence_size, retrieve_attestation_evidence
	 * is defined in libttrpc.so.
	 */
	uint32_t evidence_size = retrieve_attestation_evidence_size(guest_handle);
	if (evidence_size != sizeof(sev_evidence_t)) {
		RATS_ERR("failed to retrieve attestation evidence size, invalid size %d\n",
			 evidence_size);
		return -RATS_ATTESTER_ERR_INVALID;
	}

	sev_evidence_t *s_evidence = retrieve_attestation_evidence(guest_handle, evidence_size);
	if (!s_evidence) {
		RATS_ERR("failed to retrieve attestation_evidence\n");
		return -RATS_ATTESTER_ERR_INVALID;
	}

	sev_attestation_evidence_t *sev_report = &evidence->sev;
	memcpy(sev_report->report, s_evidence, sizeof(*s_evidence));
	sev_report->report_len = evidence_size;

	snprintf(evidence->type, sizeof(evidence->type), "sev");

	RATS_DEBUG("ctx %p, evidence %p, report_len %d\n", ctx, evidence, evidence->sev.report_len);

	return RATS_ATTESTER_ERR_NONE;
}
