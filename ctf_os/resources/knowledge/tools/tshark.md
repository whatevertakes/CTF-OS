# tshark quick sheet

Analyze local capture files with `tshark -r /work/capture.pcapng -q -z conv,tcp` and targeted display filters. Export only relevant streams or objects to `/work`, then record packet numbers and timestamps.

Validate reconstructed data against packet bytes and source hashes. Do not capture live traffic outside the supplied CTF artifact.
