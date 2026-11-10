# Source-extractive grounding

`enkstein_guard.retrieval.check_grounding` and `grounding_control` support an
explicit `mode="extractive"` option for callers that need a narrower guarantee
than citation presence. The default remains `mode="citations"` for compatibility.

## Supported response envelope

Extractive mode accepts exactly this JSON shape:

```json
{
  "answer": "Restart the ticket service during an outage.",
  "citations": [
    {
      "doc_id": "runbook",
      "quote": "Restart the ticket service during an outage."
    }
  ]
}
```

The top-level object must contain only `answer` and `citations`. Each citation
must contain only `doc_id` and `quote`. There must be 1–16 citations, the answer
and every quote must be non-empty strings, document IDs use Guard's existing
bounded ID format, and both the answer and the aggregate quotes are limited to
32 KiB of UTF-8 text. Values must use the exact JSON object, array, and string
types; SDK-only subclasses or opaque objects are not accepted. Referenced
context is limited to 256 exact-string document entries. Source strings are
conservatively capped at 1,048,576 characters, matching the maximum supported
document size without rejecting any valid stored document. SDK callers with a
custom ledger larger than 256 entries must pass the bounded request context,
not the entire ledger.

Every `doc_id` must be in the trusted recent-retrieval map supplied by the host.
Every quote is compared byte-for-byte as a substring of that document's stored
text. The answer must equal the citation quotes concatenated in their declared
order, with no inserted separator. Consequently, otherwise equivalent
whitespace, normalized Unicode, changed line breaks, summaries, paraphrases,
labels, and connective prose are rejected.

To use more than one source span, the provider must emit adjacent quotes and
set `answer` to their exact concatenation. If spaces or line breaks are needed
between spans, those characters must be included in a quoted source span.

Unknown fields, provider wrappers, nested payloads, missing or empty values,
fabricated quotes, unretrieved document IDs, oversized output, and unsupported
modes fail closed. `required=False` does not permit citation-free or invented
text in extractive mode; that option applies only to legacy citation mode.

SDK usage:

```python
ok, reason = check_grounding(response, recent_documents, mode="extractive")
control = grounding_control(recent_documents_for_operation, mode="extractive")
```

The result reasons are stable audit-oriented identifiers:

| Reason | Meaning |
| --- | --- |
| `extractive_spans_verified` | The strict envelope and every exact span passed. |
| `extractive_schema_invalid` | The envelope, fields, ID, type, count, or empty-value rule failed. |
| `extractive_output_too_large` | The answer or aggregate quotes exceeded 32 KiB. |
| `extractive_context_invalid` | The trusted context had an invalid type, source value, source size, or failed lookup. |
| `citation_not_in_retrieved_context` | A document was not in the trusted recent-retrieval map. |
| `quote_not_found_in_cited_document` | A quote was not an exact substring of its document. |
| `answer_not_source_extractive` | The answer differed from the ordered quote concatenation. |
| `unsupported_grounding_mode` | The caller selected an unknown mode. |

## Guarantee boundary

This mode establishes text provenance only for this supported response format:
released answer characters came from exact spans of authorized, recently
retrieved documents. It does not establish that a source is true, current,
complete, untampered, or free of malicious instructions. It does not prove
semantic factuality, entailment, or that adjacent source spans form a sound
conclusion. Document ingestion integrity, source governance, retrieval
authorization, and application-specific review remain separate controls.

Legacy `mode="citations"` intentionally retains its earlier behavior: markers
and citation lists establish citation presence and optional quote occurrence,
but a real citation can still accompany unsupported prose.
