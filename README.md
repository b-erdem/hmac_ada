# hmac_ada

SPARK-proved HMAC (RFC 2104) implementation in Ada/SPARK with a standalone SHA-256 (FIPS 180-4).

**175/175 SPARK checks proved, 0 assumptions, 0 warnings, Level 2.**

## Features

- HMAC-SHA-256 per RFC 2104 / RFC 4231
- 100% SPARK proved at Level 2 -- zero `pragma Assume`
- Constant-time digest comparison by default: `=` on `HMAC_Digest` is the
  constant-time operator, so `Computed = Expected` is safe against timing
  attacks. `Equal` is preserved as an explicit alias.
- Secure wipe of key material and intermediate state
- No heap allocation -- `pragma Pure`, all stack-bounded
- Streaming (Init/Update/Finalize) and one-shot (`Compute`) APIs
- Generic HMAC package for other hash functions

## Installation

```
alr with hmac_ada
```

Or add to your `alire.toml`:

```toml
[[depends-on]]
hmac_ada = "^0.2.0"
```

## Usage

### One-shot HMAC

```ada
with HMAC_SHA256;

procedure Example is
   Key : constant HMAC_SHA256.Byte_Array := (1 .. 32 => 16#42#);
   Msg : constant HMAC_SHA256.Byte_Array := (1 .. 11 => 16#48#);
   Tag : HMAC_SHA256.HMAC_Digest;
begin
   HMAC_SHA256.Compute (Key, Msg, Tag);
end Example;
```

### Streaming HMAC

```ada
with HMAC_SHA256;

procedure Example_Stream is
   Key    : constant HMAC_SHA256.Byte_Array := (1 .. 32 => 16#42#);
   Chunk1 : constant HMAC_SHA256.Byte_Array := (1 .. 64 => 16#41#);
   Chunk2 : constant HMAC_SHA256.Byte_Array := (1 .. 64 => 16#42#);
   Ctx    : HMAC_SHA256.Context;
   Tag    : HMAC_SHA256.HMAC_Digest;
begin
   HMAC_SHA256.Initialize (Ctx, Key);
   HMAC_SHA256.Update (Ctx, Chunk1);
   HMAC_SHA256.Update (Ctx, Chunk2);
   HMAC_SHA256.Finalize (Ctx, Tag);
end Example_Stream;
```

### Verifying an HMAC (constant-time)

```ada
if Computed_Tag = Expected_Tag then
   --  Valid -- comparison is constant-time
end if;
```

`HMAC_Digest` overrides `"="` with a constant-time XOR-accumulation comparison, so the default operator is already safe against timing attacks. `HMAC_SHA256.Equal` is kept as an explicit alias for code that prefers a named function.

## SPARK Proof

The concrete `HMAC_SHA256` and `SHA256` packages are fully SPARK-proved.

The generic `HMAC` package is `SPARK_Mode (Off)` because generic formal subprograms have no contracts and cannot be analyzed by gnatprove. For SPARK proof with other hash functions, write a concrete package following the `HMAC_SHA256` pattern.

## Building, Testing, and Proving

The published crate has no dev-only dependencies. Tests and `gnatprove` live in the nested `tests/` crate, which depends on the top-level crate via a local `path` pin (see [Alire docs](https://github.com/alire-project/alire/blob/master/doc/catalog-format-spec.md#using-pins-for-crate-testing)).

```bash
# Build the library
alr build

# Build and run tests (Linux)
cd tests
alr build
./obj/test_hmac

# Build and run tests (macOS -- needs SDK path for -lSystem)
cd tests
alr build -- -XSDK=macos -XSDK_LIB="$(xcrun --show-sdk-path)/usr/lib"
./obj/test_hmac

# Run SPARK proof at Level 2
cd tests
alr exec -- gnatprove -P ../hmac_ada.gpr -j0 --level=2 --timeout=120
```

26 tests cover SHA-256 (FIPS 180-4), HMAC-SHA-256 (all 7 RFC 4231 test vectors), streaming, edge cases, and the constant-time `=` operator.

## Security Considerations

- **Constant-time comparison**: `Equal` uses XOR accumulation with `pragma No_Inline` to prevent timing side-channels. This provides practical constant-time behavior with GNAT/GCC but is not a formal constant-time guarantee (which requires hardware-level analysis).
- **Key material scrubbing**: Sensitive locals are zeroed with `pragma Inspection_Point` (Ada RM H.3.2) to prevent dead-store elimination. For high-assurance environments, consider additionally using platform-specific secure wipe (e.g., `explicit_bzero`).
- **Context lifecycle**: Preconditions (`Pre` aspects) prevent calling `Update` or `Finalize` on uninitialized contexts. After `Finalize`, contexts cannot be reused without re-initializing. **Note for non-SPARK consumers**: Ada preconditions are only checked at runtime when assertion checks are enabled. If you are not using SPARK proof to verify preconditions statically, compile with `-gnata` (or `pragma Assertion_Policy (Check)`) to enable runtime enforcement. Without this, misuse of the API (e.g., calling `Update` without `Initialize`) results in undefined behavior.

## License

Apache-2.0 -- see [LICENSE](LICENSE).
