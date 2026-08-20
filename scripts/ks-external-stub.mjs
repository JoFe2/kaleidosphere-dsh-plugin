#!/usr/bin/env node

import { appendFile, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'

import {
  capabilityAttestationV2,
  executeExternalIntentV2,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'

const args = new Map()
for (let index = 2; index < process.argv.length; index += 2) {
  args.set(process.argv[index], process.argv[index + 1])
}
const readyFile = args.get('--ready')
const logFile = args.get('--log')
if (!readyFile || !logFile) {
  console.error('usage: ks-external-stub.mjs --ready <path> --log <path>')
  process.exit(2)
}

const server = createServer((request, response) => {
  const chunks = []
  request.on('data', chunk => chunks.push(chunk))
  request.on('end', async () => {
    try {
      let value
      let action = null
      if (request.method === 'GET' && request.url === '/v2/capabilities') {
        value = capabilityAttestationV2()
      } else if (request.method === 'POST' && request.url === '/v2/intents') {
        const intent = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        action = intent.action
        value = await executeExternalIntentV2(intent, {
          status: () => ({
            status: 'EXTERNAL_STUB_READY',
            sourceMode: 'fixture',
            engine: 'mssql',
            pluginVersion: 'external-v0.16.0-stub',
          }),
        })
      } else {
        response.writeHead(404).end()
        return
      }
      await appendFile(logFile, `${JSON.stringify({ method: request.method, path: request.url, action })}\n`)
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify(value))
    } catch (error) {
      response.writeHead(400, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ status: 'DENIED', code: error.code ?? error.message }))
    }
  })
})

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const address = server.address()
if (!address || typeof address === 'string') throw new Error('external stub did not acquire a TCP port')
await writeFile(readyFile, `http://127.0.0.1:${address.port}\n`)

async function close() {
  await new Promise(resolve => server.close(resolve))
  process.exit(0)
}
process.once('SIGINT', close)
process.once('SIGTERM', close)
