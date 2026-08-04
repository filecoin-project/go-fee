// driver.ts drives the real (pinned) foc-encryption reference implementation to
// (re)generate and verify the FEE cross-implementation fixtures under
// ../testdata. It is invoked by ../pull-foc-encryption.sh, which vendors the
// pinned source into ./vendor/foc-encryption and installs cborg. Run with bun:
//
//   bun driver.ts [generate|verify|all]   (default: all)
//
// generate — encrypt with foc-encryption and write the TS-produced fixtures
//            (`multi-chunk-ts`, `empty-file-ts`: TS seals, Go decrypts). A
//            fixture that already exists on disk is left alone unless
//            FEE_VECTORS_REGEN=1 is set: the reference draws a random base nonce
//            per encrypt, so regenerating rewrites a committed blob.
// verify   — decrypt every committed fixture with foc-encryption and check the
//            recovered plaintext (TS decrypts the Go-sealed blobs, and the
//            reference parses their recipient descriptors). Exits non-zero on
//            any mismatch.
import { CoseAlgorithm, decrypt, encrypt, parseEnvelope } from './vendor/foc-encryption/src/index.ts'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const HERE = import.meta.dir
const TESTDATA = join(HERE, '..', 'testdata')

// Must match the Go side (fee/vectors/helpers_test.go) and the reference
// (packages/foc-encryption/src/cose/headers.ts).
const FEE_TYP = 'application/vnd.foc-envelope+cose'
const CHUNK_SIZE = 4096

function sha256(label: string, n = 32): Uint8Array {
  return new Uint8Array(createHash('sha256').update(label).digest()).subarray(0, n)
}
const toHex = (u: Uint8Array): string => Buffer.from(u).toString('hex')
const fromHex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'))

// repeatTo returns label repeated until it reaches at least n bytes, the
// deterministic filler for a multi-chunk plaintext.
function repeatTo(label: string, n: number): Uint8Array {
  const unit = new TextEncoder().encode(label)
  const bytes: number[] = []
  while (bytes.length < n) for (const b of unit) bytes.push(b)
  return new Uint8Array(bytes)
}

// The TS-produced fixtures. Each carries its own CEK label: no two fixtures may
// share a CEK, since several are single-chunk and a shared CEK would give them
// identical chunk-0 nonces (baseNonce ‖ 0 ‖ lastFlag) over different plaintexts.
// The Go side documents the same rule on testCEK (../helpers_test.go).
const TS_FIXTURES = [
  {
    name: 'multi-chunk-ts',
    cekLabel: 'fil-473-fee-cek-ts-v1',
    description: 'AC2: multi-chunk file encrypted in foc-encryption (TS); decrypts in Go.',
    // ~15 KiB, so the STREAM spans several 4 KiB chunks.
    plaintext: () => repeatTo('multi-chunk-ts/FIL-473 ', 15000),
  },
  {
    name: 'empty-file-ts',
    cekLabel: 'fee-cek-ts-empty-v1',
    description:
      'Empty plaintext encrypted in foc-encryption (TS) (one empty final chunk, tag-only body); decrypts in Go.',
    plaintext: () => new Uint8Array(0),
  },
]

// The files every fixture directory must contain. A directory missing any of
// them is a partial write (an aborted generation) and gets rewritten.
const FIXTURE_FILES = ['blob.bin', 'plaintext.bin', 'meta.json']

async function generateTS(fixture: (typeof TS_FIXTURES)[number]): Promise<void> {
  const { name, description } = fixture
  const dir = join(TESTDATA, name)
  const complete = FIXTURE_FILES.every((f) => existsSync(join(dir, f)))
  if (complete && !process.env.FEE_VECTORS_REGEN) {
    console.log(`skipped ${name}: already on disk (set FEE_VECTORS_REGEN=1 to rewrite it)`)
    return
  }
  if (existsSync(dir) && !complete) {
    console.log(`regenerating ${name}: fixture on disk is incomplete`)
  }

  const cek = sha256(fixture.cekLabel)
  const plaintext = fixture.plaintext()

  const blob = await encrypt(plaintext, cek, {
    algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
    chunkSize: CHUNK_SIZE,
  })
  const meta = parseEnvelope(blob)

  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'blob.bin'), blob)
  writeFileSync(join(dir, 'plaintext.bin'), plaintext)
  writeFileSync(
    join(dir, 'meta.json'),
    JSON.stringify(
      {
        name,
        producer: 'ts',
        description,
        tag: 16,
        algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
        typ: FEE_TYP,
        chunk_size: meta.chunkSize ?? CHUNK_SIZE,
        chunk_count: meta.chunkCount ?? 0,
        cek_hex: toHex(cek),
      },
      null,
      2,
    ) + '\n',
  )
  console.log(`generated ${name}: blob=${blob.length}B chunks=${meta.chunkCount}`)
}

async function verifyAll(): Promise<number> {
  let failures = 0
  let checked = 0
  for (const entry of readdirSync(TESTDATA, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const dir = join(TESTDATA, entry.name)
    const present = FIXTURE_FILES.filter((f) => existsSync(join(dir, f)))
    if (present.length === 0) continue
    if (present.length < FIXTURE_FILES.length) {
      const missing = FIXTURE_FILES.filter((f) => !present.includes(f))
      console.error(`FAIL ${entry.name}: incomplete fixture, missing ${missing.join(', ')}`)
      failures++
      continue
    }

    const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8'))
    const blob = new Uint8Array(readFileSync(join(dir, 'blob.bin')))
    const expected = new Uint8Array(readFileSync(join(dir, 'plaintext.bin')))
    checked++
    try {
      const got = await decrypt(blob, fromHex(meta.cek_hex))
      if (Buffer.compare(Buffer.from(got), Buffer.from(expected)) === 0) {
        console.log(`PASS ${meta.name} (producer=${meta.producer}, tag=${meta.tag})`)
      } else {
        console.error(`FAIL ${meta.name}: recovered plaintext does not match`)
        failures++
      }
    } catch (err) {
      console.error(`FAIL ${meta.name}: ${(err as Error).message}`)
      failures++
    }
  }
  console.log(`verified ${checked} fixture(s) with foc-encryption; ${failures} failure(s)`)
  return failures
}

const mode = process.argv[2] ?? 'all'
if (mode === 'generate' || mode === 'all') for (const f of TS_FIXTURES) await generateTS(f)
let failures = 0
if (mode === 'verify' || mode === 'all') failures = await verifyAll()
if (failures > 0) {
  console.error(`cross-implementation check FAILED: ${failures} fixture(s)`)
  process.exit(1)
}
console.log('cross-implementation check OK')
