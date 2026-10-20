# Independent Blind Reviewer Handoff ??? Step 27

**Status:** prepared, not assigned or sent. Review completion remains 0/8 until authentic independent responses are received and validated.

## Before transfer

- [ ] A coordinator who is not the reviewer exports only this `blind_packet` directory as a separate review bundle.
- [ ] Do **not** include `../maintainer_key.json`, the maintainer review sheet, source labels, source metadata, or private reconciliation outputs.
- [ ] Do not grant the reviewer repository access that exposes the parent directory or Git history; provide the isolated bundle only.
- [ ] Revalidate every `email_file` SHA-256 against the packet's recorded digest using the approved packet-integrity test.
- [ ] Record the bundle hash, transfer date/time in UTC, coordinator role, and access-control location in a separate handoff log.

## Reviewer independence and completion

- [ ] Reviewer confirms they did not author, curate, or pre-label these cases and have not seen the maintainer key or original labels.
- [ ] Reviewer reads `README.md` and the rubric before reviewing.
- [ ] Complete one row per stable `review_case_id`; do not change IDs or email files.
- [ ] Record label, severity, confidence, evidence notes, reviewer role/identity in the access-controlled response, relationship to author, and `reviewed_at_utc` as ISO-8601 UTC ending in `Z`.
- [ ] Explicitly attest independence and that the blind key/original labels were not accessed. A missing attestation makes the review incomplete.
- [ ] Mark uncertainty as uncertain per the rubric; do not guess to force a label.
- [ ] Submit the completed sheet and an attestation file via the coordinator's approved secure channel. Do not add the private key to the reviewer bundle.

## Separate reconciliation and adjudication

- [ ] A different authorized maintainer validates IDs, file hashes, row count, timestamps, attestations, and schema before opening the maintainer key.
- [ ] Only after reviewer submission is sealed and hashed may a separate reconciliation process compare labels.
- [ ] Any disagreement stays unresolved until a second, independent adjudicator records their decision, rationale, identity/role, and UTC timestamp. The original reviewer and maintainer must not silently overwrite the disagreement.
- [ ] Hash the final response, attestation, reconciliation, and adjudication evidence; do not create the training approval manifest unless all required gates are met.

No reviewer identity, label, timestamp, attestation, or adjudication is prefilled by this template.
