/**
 * AWS Signature Version 4 on node:crypto, for the two AWS checks: STS
 * GetCallerIdentity (the Secret Multiscanner key, and Bedrock's IAM mode). The
 * SDK would be a large dependency for one signed POST; the spec is small, and
 * sigv4.test.ts pins this against the published aws-sig-v4-test-suite vectors.
 *
 * Deliberately narrow: no query string, a string body held in memory, and only
 * host + x-amz-date signed, plus content-type and x-amz-security-token when
 * given. That covers a form-encoded STS POST and a bare Bedrock GET.
 */
import { createHash, createHmac } from 'node:crypto'

const ALGORITHM = 'AWS4-HMAC-SHA256'

export interface AwsSigningInput {
  method: 'GET' | 'POST'
  host: string
  /** The canonical URI, already URI-encoded: '/' for STS. */
  path: string
  region: string
  service: string
  body: string
  /** Signed and sent when set: STS reads the body only as a form. */
  contentType?: string
  accessKeyId: string
  secretKey: string
  /** Temporary credentials: STS requires the token to be a SIGNED header. */
  sessionToken?: string
  now: Date
}

export interface AwsSignature {
  canonicalRequest: string
  stringToSign: string
  signedHeaders: string
  signature: string
  /**
   * The headers to send. Host is signed but not returned: fetch derives it
   * from the URL, which carries the same host.
   */
  headers: Record<string, string>
}

function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex')
}

function hmac(key: string | Buffer, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest()
}

/** 2015-08-30T12:36:00.000Z -> 20150830T123600Z (the x-amz-date format). */
export function amzDate(now: Date): string {
  return now.toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '')
}

export function signingKey(secretKey: string, dateStamp: string, region: string, service: string): Buffer {
  return hmac(hmac(hmac(hmac(`AWS4${secretKey}`, dateStamp), region), service), 'aws4_request')
}

/** The spec's canonical header value: trimmed, inner runs of spaces collapsed. */
function canonicalValue(value: string): string {
  return value.trim().replace(/ +/g, ' ')
}

export function sigV4(input: AwsSigningInput): AwsSignature {
  const date = amzDate(input.now)
  const dateStamp = date.slice(0, 8)
  const scope = `${dateStamp}/${input.region}/${input.service}/aws4_request`

  const signed: Record<string, string> = { host: input.host, 'x-amz-date': date }
  if (input.contentType) signed['content-type'] = input.contentType
  if (input.sessionToken) signed['x-amz-security-token'] = input.sessionToken
  const names = Object.keys(signed).sort()
  const signedHeaders = names.join(';')

  const canonicalRequest = [
    input.method,
    input.path,
    '',
    names.map(n => `${n}:${canonicalValue(signed[n])}\n`).join(''),
    signedHeaders,
    sha256Hex(input.body),
  ].join('\n')
  const stringToSign = [ALGORITHM, date, scope, sha256Hex(canonicalRequest)].join('\n')
  const signature = hmac(signingKey(input.secretKey, dateStamp, input.region, input.service), stringToSign).toString('hex')

  const headers: Record<string, string> = {}
  if (input.contentType) headers['Content-Type'] = input.contentType
  headers['X-Amz-Date'] = date
  if (input.sessionToken) headers['X-Amz-Security-Token'] = input.sessionToken
  headers.Authorization = `${ALGORITHM} Credential=${input.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`

  return { canonicalRequest, stringToSign, signedHeaders, signature, headers }
}

/** The headers that authenticate the request (the secret key itself is never among them). */
export function signAwsRequest(input: AwsSigningInput): Record<string, string> {
  return sigV4(input).headers
}
