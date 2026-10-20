# Fresh phishing-specific provisional evaluation dataset

## Sources and licensing
- Positive: Nazario phishing corpus 2025, https://monkey.org/~jose/phishing/phishing-2025. README: https://monkey.org/~jose/phishing/README; license: https://monkey.org/~jose/phishing/LICENSE.txt. Source README identifies CC-BY-4.0; attribution required.
- Negative: CMU Enron Email Dataset May 2015 archive, https://www.cs.cmu.edu/~enron/ and https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz. No clear standard corpus-wide license identified; internal evaluation only, legal review pending. The script streams the archive and keeps a bounded number of messages.

## Labels and protocol
All rows are labelled PROVISIONAL: dataset-curator labelled, not human-reviewed. Nazario phishing-folder provenance and Enron corpus provenance are proxy labels, not project-team adjudications. Raw data and manifests are ignored by Git and must not be committed.

The script uses deterministic seed 20261016, removes exact SHA-256 matches against the previous SpamAssassin holdout, and creates a balanced holdout of up to 100 phishing and 100 ham messages. Remaining messages are split into train/dev. The holdout manifest is checksummed. Do not tune on holdout. Candidate selection is dev-only; --final is single-use and guarded by a run log.

## Commands
backend/venv/Scripts/python.exe backend/scripts/prepare_phishing_specific_corpus.py
backend/venv/Scripts/python.exe backend/scripts/evaluate_phishing_policy.py --dev
backend/venv/Scripts/python.exe backend/scripts/evaluate_phishing_policy.py --smoke
backend/venv/Scripts/python.exe backend/scripts/evaluate_phishing_policy.py --final

Prepared manifests and final run log are under backend/data/phishing_specific_corpus/prepared/. Do not remove/reset the final run log to repeat evaluation.
