#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <librats/api.h>
#include <librats/evidence.h>
#include <librats/log.h>

#define HEX_DUMP_SIZE  64
#define BYTES 4

static void print_hex_dump(const char *title, const char *prefix_str,
                const uint8_t *buf, int len)
{
        const uint8_t *ptr = buf;
        int i, k, rowsize = HEX_DUMP_SIZE;

        if (!len || !buf)
                return;

        printf("\t\t%s", title);

        for (i = 0; i < len; ) {
            if (!(i % rowsize))
                    printf("\n%s%.8x:", prefix_str, i);
            if (i + BYTES < len) {
                for (k = 0; k < BYTES; k++) {
                    if (ptr[i+k] <= 0x0f)
                            printf("0%x", ptr[i]);
                    else
                            printf("%x", ptr[i]);
                }
                printf(" ");
            } else {
                for (k = 0; k < len-i; k++) {
                    if (ptr[i+k] <= 0x0f)
                            printf("0%x", ptr[i]);
                    else
                            printf("%x", ptr[i]);
                }
            }
            i += BYTES;
        }

        printf("\n");
}

int main(int argc, char **argv)
{
    attestation_evidence_t evidence;
    const char *hash = "12345678123456781234567812345678";

    rats_attester_err_t ret = librats_collect_evidence(&evidence, hash);
    if (ret != RATS_ATTESTER_ERR_NONE) {
        RATS_ERR("Librats collect evidence failed. Return code: %#x\n", ret);
        return -1;
    }

    print_hex_dump("\n\t\tTDX evidence data\n", " ", (uint8_t*)&evidence, sizeof(evidence));
    FILE *fptr = fopen("evidence.dat","wb");
    if( fptr )
    {
        fwrite(&evidence, sizeof(evidence), 1, fptr);
        fclose(fptr);
    }

    rats_verifier_err_t ver_ret = librats_verify_evidence(&evidence, hash, NULL, NULL);
    if (ver_ret != RATS_VERIFIER_ERR_NONE) {
        RATS_ERR("Failed to verify evidence. Return code: %#x\n", ver_ret);
        return -1;
    } else {
        RATS_INFO("Evidence is trusted.\n");
    }

    return 0;
}

