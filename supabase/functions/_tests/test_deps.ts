// Test-only dependencies (pinned). `_tests` is underscore-prefixed, so the
// Supabase CLI never treats it as a function.
export {
  assert,
  assertEquals,
  assertFalse,
  assertMatch,
  assertNotEquals,
  assertThrows,
} from 'jsr:@std/assert@1.0.13';
