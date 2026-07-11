# binwalk quick sheet

Start read-only: `binwalk /work/artifact` and save the output. Extract only a copied artifact into `/work/extracted`, then hash every derivative and inspect it with `file`.

Confirm a reported offset against the source bytes and document tool version. Recursive extraction is a hypothesis aid, not proof of intended hidden data.
