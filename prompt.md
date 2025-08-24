Your job is to build an amd64 emulator with unicorn-engine based API (which is in turn build on QEMU) in pure rust and maintain the repository.

Make a commit after every single file edit.

Use the .agent/ directory as a scratchpad for your work. Store long term plans and todo lists there.

When porting, you will need to write end to end and unit tests for the project. But make sure to spend most of your time on the actual porting, not on the testing. A good heuristic is to spend 80% of your time on the actual porting, and 20% on the testing. Implement instrumentation and tracing as well as tests as necessary to help with correctness and debugging.
