# Misc playbook

## Scope and recon

Inventory every supplied file and the exact challenge text before choosing a category. Use local-only inspection first, record file types, encodings, protocols, puzzle rules, and prior failed approaches. Keep experiments in `/work` and durable evidence in `/artifacts`.

## Hypotheses and tooling

Favor the simplest evidence-backed branch: media transforms with `ffmpeg`/`sox`, image or QR/barcode inspection with ImageMagick/OpenCV/`zbarimg`, signal or numeric work with NumPy/SciPy, graph constraints with NetworkX/Graphviz, z3 constraints, custom protocols with Scapy, or ML-flavored artifacts with CPU PyTorch. Use short scripts with fixed inputs and explicit bounds. Podman is limited to rootless local container/image inspection; there is no Docker socket or privileged nested daemon.

## Validation and replay

Check a solution against all stated constraints and independently rerun it from saved inputs. Save the minimal solver, command, outputs, and assumptions. If an approach repeats the same failure, write a SHIFT note and move to a different class of hypothesis.
