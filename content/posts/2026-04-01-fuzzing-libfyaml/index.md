---
title: "Fuzzing libfyaml"
description: Fuzzing a C YAML parsing library with libFuzzer
date: 2026-04-01T12:00:00Z
categories:
    - fuzzing
    - security
    - opensource
---

I spent some time fuzzing [libfyaml](https://github.com/pantoniou/libfyaml), a feature-rich YAML parser/emitter written in C. I ended up finding and reporting 68 bugs, all of which have been fixed by the maintainer. Here's how it went.

## Target

libfyaml is a YAML library that supports YAML 1.2. It provides a pretty extensive API - parsing, emitting, path expressions, document manipulation, a reflection/type system, and more. It's written in C, which makes it a great candidate for fuzzing with sanitizers.

The library has a lot of surface area. Beyond basic parse/emit, there are features like path queries, document traversal, alias resolution, tree manipulation (insert, remove, sort), and a whole reflection system for mapping YAML to C types. Plenty of code paths to explore.

## Tooling

I used [libFuzzer](https://llvm.org/docs/LibFuzzer.html) as the fuzzing engine, combined with:

- **AddressSanitizer (ASan)** - for detecting memory errors (use-after-free, buffer overflows, memory leaks)
- **UndefinedBehaviorSanitizer (UBSan)** - for catching undefined behavior (signed integer overflow, invalid casts, etc.)

The build flags looked like this:

```
-fsanitize=fuzzer,address,signed-integer-overflow,undefined
```

I also had a separate reproducer binary (without the fuzzer sanitizer linked in) for debugging and triaging crashes outside of the fuzzing loop.

## Fuzzer design

I went with a single-harness, multi-target approach. Instead of writing separate fuzzers for each API, I wrote one harness that exercises as many code paths as possible in a single run.

### Input data structure

Each fuzzer input is split into two parts: a **header** and the **actual fuzz data**.

The header occupies the first 36 bytes of the input. It's a struct of 9 `uint32_t` fields, each controlling a different aspect of the library's configuration:

```c
struct seed_data_t {
  uint32_t seed1;  // parser flags
  uint32_t seed2;  // emitter flags
  uint32_t seed3;  // traversal flags
  uint32_t seed4;  // path query parser flags
  uint32_t seed5;  // output style
  uint32_t seed6;  // extended emitter flags
  uint32_t seed7;  // primitive type selection
  uint32_t seed8;  // type info flags
  uint32_t seed9;  // C generation flags
  struct flags_t *flags;
} __attribute__((aligned(16)));
```

- **seed1** - parser flags (YAML version, document resolution, caching, depth limits, JSON mode, alias expansion, duplicate key handling, ...)
- **seed2** - emitter flags (sort keys, output mode like block/flow/JSON/pretty, indentation, width, document markers, ...)
- **seed3** - traversal flags (follow mode, pointer type like YAML/JSON/path query, URI encoding, max depth, ...)
- **seed4** - path query parser flags (caching, performance optimizations)
- **seed5** - output style (any, flow, block, plain, single/double quoted, literal, folded, alias)
- **seed6** - extended emitter flags (color, visible whitespace, extended indicators, ...) with output destination bits masked off to avoid side effects
- **seed7** - primitive type selection (bool, char, int, float, double, etc. - for the reflection system)
- **seed8** - type qualifier flags (const, volatile, restrict, anonymous, incomplete, ...)
- **seed9** - C code generation flags (indentation style, comment format)

A setup function translates these raw seeds into the actual flag values used by the library. Most seeds are used directly as bitmasks. For enum-like fields (output style, primitive type, C generation flags), the seed is taken modulo the number of valid values to pick one from a predefined list. The extended emitter flags mask off output destination bits to avoid side effects like writing to stdout/stderr/files during fuzzing. This means the coverage-guided engine has a direct, transparent mapping between input bytes and every configuration bit. When the fuzzer mutates bytes 0-35, it's directly toggling library features.

In the fuzzer entry point, the header is extracted at the start of each iteration:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= sizeof(struct seed_data_t)) return 0;

  struct flags_t flags = {0};
  struct seed_data_t _seed;
  struct seed_data_t *seed = &_seed;
  memcpy(seed, (struct seed_data_t *)data, sizeof(struct seed_data_t));
  setup_flags(seed, &flags);
  seed->flags = &flags;
  data += sizeof(struct seed_data_t);
  size -= sizeof(struct seed_data_t);

  // ... run all tests with remaining data ...
}
```

Everything after byte 36 is the fuzz data - the YAML content. For string-based APIs, this data is null-terminated before being passed to the library. For binary/file-pointer APIs, the raw bytes are passed directly as an in-memory file stream.

### Why this approach

The main reason I went with a header-based design instead of, say, using `FuzzedDataProvider` to consume bytes on the fly, is **transparency for the fuzzing engine**. With a fixed-offset header, libFuzzer can directly correlate specific byte positions with specific code coverage changes. If flipping a bit at offset 0 enables a feature like document resolution and that opens up a new code path, the fuzzer learns that immediately. With a stream-based approach, the relationship between byte positions and their effects shifts depending on how many bytes were consumed before, which makes it harder for the engine to learn.

It also keeps things simple. The struct layout is fixed, so reproducing a crash is trivial - just look at the first 36 bytes to know exactly what configuration was active.

### Disadvantages

This approach has real downsides. Running 35+ tests on every input is slow. Each fuzzer iteration does a lot of redundant work - most tests will likely reject or quickly bail out on an input that was really only useful for one or two of them. This directly hurts the executions-per-second metric, which is one of the most important factors in fuzzing effectiveness.

There's also the fixed header overhead. Every input must be at least 37 bytes long (36 for the header + at least 1 byte of data), and the first 36 bytes are always "spent" on configuration rather than actual YAML content. For a library where interesting bugs can hide in short, carefully crafted inputs, wasting 36 bytes on a header is not ideal. The fuzzer has to work harder to find minimally-sized triggering inputs.

Another issue is that the same fuzz data is shared across all tests with wildly different expectations. A path query parser expects something like `/foo/bar`, while the YAML parser expects valid YAML, and the reflection system expects packed binary blobs. The same input can't realistically be good for all of them at once, so most tests end up exercising only their error/early-exit paths for any given input.

A more disciplined approach would be to write separate harnesses per feature group, or at least use the header to dispatch to a single test per iteration. That said, the brute-force approach worked well enough here - it found 68 bugs, so I can't complain too much.

## Findings

In total, I reported **68 issues** to the libfyaml GitHub repository. All of them have been acknowledged and fixed by the maintainer. Here's a breakdown by category:

- **Heap-use-after-free (26)** - the most common class, appearing across parsing, emitting, path queries, reference counting, iteration, alias handling, and list operations. Includes one double-free.
- **Memory leaks (16)** - memory not properly freed on error paths or during cleanup, spread across parsing, emitting, path queries, alias handling, and the type reflection system.
- **Buffer overflows (9)** - heap, stack, and global buffer overflows in internal array resizing, UTF-8 decoding, path traversal, output setup, and token processing.
- **Undefined behavior (7)** - infinity-to-integer conversions, signed integer overflow, misaligned memory access in a bundled hash function, and related issues in output and text handling.
- **Null dereference / SIGSEGV (4)** - null pointer dereferences in path query construction, line iteration, and input handling, triggered by specific combinations of parser flags.
- **Stack overflows (2)** - infinite recursion when document resolution and alias expansion were enabled together.
- **Infinite loops (2)** - hangs during document construction with alias resolution.
- **Out-of-memory (1)** - a path query consuming unbounded memory.
- **API/documentation issue (1)** - a function referenced in the documentation that didn't exist in the library.

All issues were reported with reproducer inputs and sanitizer stack traces. The maintainer was responsive and fixed everything. The full list of reports can be found on the [libfyaml issues page](https://github.com/pantoniou/libfyaml/issues?q=is%3Aissue%20author%3Arivit98).

## A note on AI

Every single one of these 68 bugs was found without any AI assistance. The fuzzer was written by hand, the triage was done manually, and the reports were filed by a human.

I originally had plans to turn some of the more interesting bugs (particularly the use-after-free ones) into a CTF challenge. But in the current AI era, where LLMs can solve most CTF challenges without much effort, I decided not to waste time on that. It just doesn't feel worth the effort anymore when the solution process can be shortcut so easily.

## Summary

Fuzzing libfyaml turned out to be quite productive. 68 bugs across a wide range of categories - from use-after-free and buffer overflows to memory leaks and undefined behavior. The single-harness multi-target approach worked well here because the library has so many interconnected features that benefit from being exercised together.
