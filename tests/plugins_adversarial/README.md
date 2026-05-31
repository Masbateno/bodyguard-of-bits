# Adversarial plugins — known-bad suite

These plugins exist to test the BOB sandbox runner (`bob/_sandbox.py`).
Each one attempts a different escape vector. The `tests/test_plugin_sandbox.py`
suite loads them through the runner and asserts that the attack failed:

  - The plugin must NOT successfully perform its destructive intent.
  - The plugin must NOT crash the audit run (errors return a WARN finding).
  - When applicable, side-effects (FS writes, subprocess spawns) must NOT have happened.

Pattern coverage (per Q4 of project_v07x_phase2 T3 design discussion):

  01_subprocess_direct      — direct `subprocess` import
  02_subprocess_via_os      — `os.system()`
  03_eval_subprocess        — `eval()` runtime construction
  04_exec_subprocess        — `exec()` runtime construction
  05_ctypes_execve          — ctypes-based libc execve
  06_file_write_pathlib     — `Path.write_text` persistence
  07_file_write_open        — `open(..., "w")` persistence
  08_socket_outbound        — `socket.connect()` outbound connection
  09_thread_runaway         — `threading.Thread` background spawn
  10_os_fork                — `os.fork()` process duplication
  11_dunder_import_bypass   — `__import__()` direct call
  12_globals_pollute        — `globals()` / `__builtins__` mutation
  13_environ_set            — `os.environ` mutation (LD_PRELOAD class)
  14_memory_bomb            — large allocation (OOM attempt)
  15_infinite_loop          — CPU starvation (`while True`)

DO NOT add these plugins to `~/.config/bob/checks.d/` — they are intentionally
malicious for testing only.
