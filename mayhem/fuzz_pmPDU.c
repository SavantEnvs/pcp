#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcp/pmapi.h>
#include <pcp/libpcp.h>

/* libpcp reads its config lazily (pmgetconfig) and exit(1)s without a pcp.conf; point it at the built one. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    setenv("PCP_CONF", "/mayhem/src/include/pcp.conf", 0);
    return 0;
}

/*
 * Feed an attacker-controlled PDU body (what pmcd/pmlogger/pmproxy read off a socket) to one of
 * libpcp's PDU decoders.  First byte selects the decoder; the rest is the PDU after its header.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const int types[] = {
	PDU_ERROR, PDU_RESULT, PDU_HIGHRES_RESULT, PDU_PROFILE, PDU_FETCH, PDU_HIGHRES_FETCH,
	PDU_DESC_REQ, PDU_DESC, PDU_DESCS, PDU_INSTANCE_REQ, PDU_INSTANCE, PDU_TEXT_REQ,
	PDU_TEXT, PDU_CREDS, PDU_PMNS_IDS, PDU_PMNS_NAMES, PDU_PMNS_CHILD, PDU_PMNS_TRAVERSE,
	PDU_ATTR, PDU_LABEL_REQ, PDU_LABEL, PDU_DESC_IDS
    };
    const int ndec = (int)(sizeof(types) / sizeof(types[0]));
    __pmPDU *pdu;
    __pmPDUHdr *hdr;
    int sel, total, a = 0, b = 0, sts;

    if (size < 1)
	return -1;
    sel = data[0] % ndec;
    total = (int)sizeof(__pmPDUHdr) + (int)(size - 1);
    pdu = __pmFindPDUBuf(total);
    if (pdu == NULL)
	return -1;
    memcpy((char *)pdu + sizeof(__pmPDUHdr), data + 1, size - 1);
    hdr = (__pmPDUHdr *)pdu;
    hdr->len = total;
    hdr->type = types[sel];
    hdr->from = 0;

    switch (sel) {
    case 0:
	__pmDecodeError(pdu, &a);
	break;
    case 1: {
	__pmResult *r = NULL;
	if (__pmDecodeResult(pdu, &r) >= 0)
	    __pmFreeResult(r);
	break;
    }
    case 2: {
	__pmResult *r = NULL;
	if (__pmDecodeHighResResult(pdu, &r) >= 0)
	    __pmFreeResult(r);
	break;
    }
    case 3: {
	pmProfile *prof = NULL;
	if (__pmDecodeProfile(pdu, &a, &prof) >= 0)
	    __pmFreeProfile(prof);
	break;
    }
    case 4: {
	pmID *ids = NULL;
	char when[32];
	/* a successful decode pins the PDU buffer again; pmcd drops that pin via the id list */
	if (__pmDecodeFetch(pdu, &a, when, &b, &ids) >= 0)
	    __pmUnpinPDUBuf(ids);
	break;
    }
    case 5: {
	pmID *ids = NULL;
	int c = 0;
	if (__pmDecodeHighResFetch(pdu, &a, &c, &ids) >= 0)
	    __pmUnpinPDUBuf(ids);
	break;
    }
    case 6: {
	pmID id;
	__pmDecodeDescReq(pdu, &id);
	break;
    }
    case 7: {
	pmDesc d;
	__pmDecodeDesc(pdu, &d);
	break;
    }
    case 8: {
	pmDesc *d = NULL;
	if (__pmDecodeDescs2(pdu, &a, &d) >= 0)
	    free(d);
	break;
    }
    case 9: {
	pmInDom indom;
	char *name = NULL;
	if (__pmDecodeInstanceReq(pdu, &indom, &a, &name) >= 0)
	    free(name);
	break;
    }
    case 10: {
	pmInResult *ir = NULL;
	if (__pmDecodeInstance(pdu, &ir) >= 0)
	    __pmFreeInResult(ir);
	break;
    }
    case 11:
	__pmDecodeTextReq(pdu, &a, &b);
	break;
    case 12: {
	char *text = NULL;
	if (__pmDecodeText(pdu, &a, &text) >= 0)
	    free(text);
	break;
    }
    case 13: {
	__pmCred *creds = NULL;
	if (__pmDecodeCreds(pdu, &a, &b, &creds) >= 0)
	    free(creds);
	break;
    }
    case 14:
    case 21: {
	pmID *ids = NULL;
	sts = __pmDecodeIDList2(pdu, &a, &ids);
	if (sts >= 0)
	    free(ids);
	break;
    }
    case 15: {
	char **names = NULL;
	int *status = NULL;
	if (__pmDecodeNameList(pdu, &a, &names, &status) >= 0) {
	    free(names);
	    free(status);
	}
	break;
    }
    case 16: {
	char *name = NULL;
	if (__pmDecodeChildReq(pdu, &name, &a) >= 0)
	    free(name);
	break;
    }
    case 17: {
	char *name = NULL;
	if (__pmDecodeTraversePMNSReq(pdu, &name) >= 0)
	    free(name);
	break;
    }
    case 18: {
	char *v = NULL;
	__pmDecodeAttr(pdu, &a, &v, &b);
	break;
    }
    case 19:
	__pmDecodeLabelReq(pdu, &a, &b);
	break;
    default: {
	pmLabelSet *sets = NULL;
	int c = 0;
	if (__pmDecodeLabel(pdu, &a, &b, &sets, &c) >= 0)
	    pmFreeLabelSets(sets, c);
	break;
    }
    }
    __pmUnpinPDUBuf(pdu);
    return 0;
}
