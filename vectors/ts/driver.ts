// driver.ts drives the real (pinned) TypeScript FEE reference,
// @filoz/filecoin-encryption-envelope from synapse-sdk, to (re)generate and
// verify the FEE cross-implementation fixtures under ../testdata. It is invoked
// by ../pull-synapse-fee.sh, which vendors the pinned source into
// ./vendor/filecoin-encryption-envelope and installs its dependencies. Run with
// Node, which strips the TypeScript types itself:
//
//   node driver.ts [generate|verify|all]   (default: all)
//
// generate — encrypt with the reference and write the TS-produced fixtures
//            (`multi-chunk-ts`, `empty-file-ts`, `kidless-recipient-ts`: TS
//            seals, Go decrypts). A
//            fixture that already exists on disk is left alone unless
//            FEE_VECTORS_REGEN=1 is set: the reference draws a random base nonce
//            per encrypt, so regenerating rewrites a committed blob.
// verify   — for every committed fixture, decrypt the whole object from the CEK,
//            decrypt a range from the CEK, and unwrap the CEK from each A256KW
//            recipient with a key that has its kid and with one that has none,
//            checking the recovered plaintext each time (TS reads the
//            Go-sealed blobs). Exits non-zero on any mismatch.
import * as fee from './vendor/filecoin-encryption-envelope/src/index.ts'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const HERE = import.meta.dirname
const TESTDATA = join(HERE, '..', 'testdata')

// Must match the Go side (fee/vectors/helpers_test.go) and FIP-1253.
const FEE_TYP = 'application/vnd.filecoin-encryption+cose'
const ALG_CHUNKED = -65793
const ALG_A256KW = -5
const CHUNK_SIZE = 4096

function sha256(label: string, n = 32): Uint8Array {
  return new Uint8Array(createHash('sha256').update(label).digest()).subarray(0, n)
}
const toHex = (u: Uint8Array): string => Buffer.from(u).toString('hex')
const fromHex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'))
const equal = (a: Uint8Array, b: Uint8Array): boolean => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0

// repeatTo returns label repeated until it reaches at least n bytes, the
// deterministic filler for a multi-chunk plaintext.
function repeatTo(label: string, n: number): Uint8Array {
  const unit = new TextEncoder().encode(label)
  const bytes: number[] = []
  while (bytes.length < n) for (const b of unit) bytes.push(b)
  return new Uint8Array(bytes)
}

// through pipes bytes through one of the reference's transform pairs and
// collects the output.
async function through(input: Uint8Array, pair: ReadableWritablePair<Uint8Array, Uint8Array>): Promise<Uint8Array> {
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      if (input.length > 0) controller.enqueue(new Uint8Array(input))
      controller.close()
    },
  })
  return new Uint8Array(await new Response(source.pipeThrough(pair)).arrayBuffer())
}

const collect = async (stream: ReadableStream<Uint8Array>): Promise<Uint8Array> =>
  new Uint8Array(await new Response(stream).arrayBuffer())

// The TS-produced fixtures. Each carries its own CEK label: no two fixtures may
// share a CEK, since several are single-chunk and a shared CEK would give them
// identical chunk-0 nonces (baseNonce ‖ 0 ‖ lastFlag) over different plaintexts.
// The Go side documents the same rule on testCEK (../helpers_test.go). A
// fixture with a kekLabel gets one A256KW recipient without a kid (tag 96).
const TS_FIXTURES: {
  name: string
  cekLabel: string
  kekLabel?: string
  description: string
  plaintext: () => Uint8Array
}[] = [
  {
    name: 'multi-chunk-ts',
    cekLabel: 'fil-473-fee-cek-ts-v1',
    description: 'AC2: multi-chunk file encrypted in filecoin-encryption-envelope (TS); decrypts in Go.',
    // ~15 KiB, so the STREAM spans several 4 KiB chunks.
    plaintext: () => repeatTo('multi-chunk-ts/FIL-473 ', 15000),
  },
  {
    name: 'empty-file-ts',
    cekLabel: 'fee-cek-ts-empty-v1',
    description:
      'Empty plaintext encrypted in filecoin-encryption-envelope (TS) (one empty final chunk, tag-only body); decrypts in Go.',
    plaintext: () => new Uint8Array(0),
  },
  {
    name: 'kidless-recipient-ts',
    cekLabel: 'fee-cek-ts-kidless-v1',
    kekLabel: 'fee-kek-ts-kidless-v1',
    description:
      'A256KW recipient without a kid, encrypted in filecoin-encryption-envelope (TS); Go unwraps it by trying its key.',
    plaintext: () => new TextEncoder().encode('FEE cross-impl vector: an A256KW recipient with no kid, sealed in TS.\n'),
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
  const kek = fixture.kekLabel === undefined ? undefined : sha256(fixture.kekLabel)
  const plaintext = fixture.plaintext()
  const blob = await through(
    plaintext,
    fee.encrypt({
      cek: new Uint8Array(cek),
      chunkSize: CHUNK_SIZE,
      contentLength: plaintext.length,
      ...(kek === undefined ? {} : { recipients: [{ alg: ALG_A256KW, kek: new Uint8Array(kek) }] }),
    }),
  )
  const info = await fee.parse(blob)
  if (info.scheme !== 'chunked') throw new Error(`${name}: expected a chunked envelope, got ${info.scheme}`)
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / info.params.chunkSize))

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
        tag: kek === undefined ? 16 : 96,
        algorithm: ALG_CHUNKED,
        typ: FEE_TYP,
        chunk_size: info.params.chunkSize,
        chunk_count: chunkCount,
        cek_hex: toHex(cek),
        ...(kek === undefined
          ? {}
          : { recipients: [{ algorithm: ALG_A256KW, kind: 'a256kw', a256kw_kek_hex: toHex(kek) }] }),
      },
      null,
      2,
    ) + '\n',
  )
  console.log(`generated ${name}: blob=${blob.length}B chunks=${chunkCount}`)
}

// verifyFixture runs every check the reference can make on one fixture and
// returns the failures it found.
async function verifyFixture(meta: any, blob: Uint8Array, expected: Uint8Array): Promise<string[]> {
  const failures: string[] = []
  const cek = fromHex(meta.cek_hex)

  const whole = await through(blob, fee.decrypt(new Uint8Array(cek)))
  if (!equal(whole, expected)) failures.push('whole-object plaintext does not match')

  // A range from the middle of the object, when it has bytes to address.
  if (expected.length > 0) {
    const offset = Math.floor(expected.length / 3)
    const length = Math.min(100, expected.length - offset)
    const result = await fee.decryptRange(blob, new Uint8Array(cek), { offset, length })
    const got = await collect(result.stream)
    if (!equal(got, expected.subarray(offset, offset + length))) failures.push(`range ${offset}+${length} does not match`)
    if (result.totalPlaintextLength !== expected.length) {
      failures.push(`range reports ${result.totalPlaintextLength} plaintext bytes, want ${expected.length}`)
    }
  }

  for (const r of meta.recipients ?? []) {
    if (r.kind !== 'a256kw') continue
    // A key with the recipient's kid (if it has one), then a key with none,
    // which the reference tries against every A256KW recipient.
    const kek = fromHex(r.a256kw_kek_hex)
    const keys = r.kid_hex === undefined ? [{ kek }] : [{ kek, kid: fromHex(r.kid_hex) }, { kek }]
    for (const key of keys) {
      const unwrapper = await fee.recipients.createA256KWUnwrapper([key])
      const got = await through(blob, fee.decryptWith(unwrapper))
      const which = key.kid === undefined ? 'a key without a kid' : 'a key with its kid'
      if (!equal(got, expected)) failures.push(`plaintext via the A256KW recipient, with ${which}, does not match`)
    }
  }
  return failures
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
      const problems = await verifyFixture(meta, blob, expected)
      if (problems.length === 0) {
        console.log(`PASS ${meta.name} (producer=${meta.producer}, tag=${meta.tag})`)
      } else {
        for (const p of problems) console.error(`FAIL ${meta.name}: ${p}`)
        failures++
      }
    } catch (err) {
      console.error(`FAIL ${meta.name}: ${(err as Error).message}`)
      failures++
    }
  }
  console.log(`verified ${checked} fixture(s) with filecoin-encryption-envelope; ${failures} failure(s)`)
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
