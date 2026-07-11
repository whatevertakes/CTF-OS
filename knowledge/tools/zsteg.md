# zsteg quick sheet

For a supplied PNG or BMP, run `zsteg /work/image.png` and record candidate channels, bit planes, and payload offsets. Extract one candidate at a time to `/work` and identify it with `file`.

Validate a finding by reproducing the same extraction with the recorded channel settings. Avoid assuming every printable result is meaningful.
