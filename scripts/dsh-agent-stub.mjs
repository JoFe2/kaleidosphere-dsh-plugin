#!/usr/bin/env node

import { appendFile, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'

const args = new Map()
for (let index = 2; index < process.argv.length; index += 2) {
  args.set(process.argv[index], process.argv[index + 1])
}

const readyFile = args.get('--ready')
const logFile = args.get('--log')
if (!readyFile || !logFile) {
  console.error('usage: dsh-agent-stub.mjs --ready <path> --log <path>')
  process.exit(2)
}

const KS_TOOLS = [
  'kaleidosphere_status',
  'kaleidosphere_discovery',
  'kaleidosphere_analyze',
  'kaleidosphere_plan',
  'kaleidosphere_preview',
  'kaleidosphere_readback',
]
const SNAPSHOT = '293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a'

function toolResult(body) {
  return body.messages?.findLast(message => message.role === 'tool')
}

function toolCall(name, callArgs, callId) {
  return [
    { choices: [{ delta: { role: 'assistant', content: '', reasoning_content: '' } }] },
    {
      choices: [{
        delta: {
          tool_calls: [{
            index: 0,
            id: callId,
            type: 'function',
            function: { name, arguments: JSON.stringify(callArgs) },
          }],
        },
      }],
    },
    {
      choices: [{ delta: {}, finish_reason: 'tool_calls' }],
      usage: { prompt_tokens: 20, completion_tokens: 4 },
    },
  ]
}

function answer(text) {
  return [
    { choices: [{ delta: { role: 'assistant', content: null, reasoning_content: '' } }] },
    { choices: [{ delta: { content: text } }] },
    {
      choices: [{ delta: { content: '' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 24, completion_tokens: 8 },
    },
  ]
}

function responseFor(scenario, body) {
  const result = toolResult(body)
  const prompt = body.messages?.find(message => message.role === 'user')?.content
  if (typeof prompt === 'string' && prompt.startsWith('Generate the session title')) {
    return { kind: 'session-title', events: answer('KaleidoSphere fixture analysis') }
  }
  if (scenario === 'happy') {
    if (!result) {
      return { kind: 'forced-tool-call', events: toolCall('kaleidosphere_analyze', {}, 'ks-happy-analyze') }
    }
    const content = String(result.content ?? '')
    const digest = content.includes(SNAPSHOT) ? SNAPSHOT : 'missing'
    return {
      kind: 'answer-after-tool-result',
      events: answer(`KS_AGENT_HAPPY engine=mssql snapshot=${digest}`),
    }
  }
  if (scenario === 'malformed') {
    if (!result) {
      return { kind: 'forced-malformed-tool-call', events: toolCall('kaleidosphere_plan', {}, 'ks-malformed-plan') }
    }
    return {
      kind: 'answer-after-tool-error',
      events: answer(`KS_AGENT_MALFORMED_REJECTED ${String(result.content ?? '').slice(0, 240)}`),
    }
  }
  if (['no-plugin', 'disabled', 'removed'].includes(scenario)) {
    return { kind: 'answer-without-tool', events: answer(`KS_AGENT_UNAVAILABLE scenario=${scenario}`) }
  }
  throw new Error(`unsupported scenario: ${scenario}`)
}

const server = createServer((request, response) => {
  let raw = ''
  request.setEncoding('utf8')
  request.on('data', chunk => { raw += chunk })
  request.on('end', async () => {
    try {
      const scenario = new URL(request.url ?? '/', 'http://stub.invalid').pathname.split('/').filter(Boolean)[0]
      const body = JSON.parse(raw)
      const scripted = responseFor(scenario, body)
      const advertisedTools = (body.tools ?? []).map(tool => tool.function?.name).filter(Boolean)
      await appendFile(logFile, `${JSON.stringify({
        scenario,
        requestPath: request.url,
        authorizationPresent: typeof request.headers.authorization === 'string',
        ksTools: advertisedTools.filter(name => KS_TOOLS.includes(name)),
        userPrompt: body.messages?.find(message => message.role === 'user')?.content ?? null,
        toolResult: toolResult(body)?.content ?? null,
        responseKind: scripted.kind,
      })}\n`)
      response.writeHead(200, { 'content-type': 'text/event-stream' })
      for (const event of scripted.events) response.write(`data: ${JSON.stringify(event)}\n\n`)
      response.end('data: [DONE]\n\n')
    } catch (error) {
      response.writeHead(500, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ error: { message: error.message } }))
    }
  })
})

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const address = server.address()
if (!address || typeof address === 'string') throw new Error('stub did not acquire a TCP port')
await writeFile(readyFile, `http://127.0.0.1:${address.port}\n`)

async function close() {
  await new Promise(resolve => server.close(resolve))
  process.exit(0)
}

process.once('SIGINT', close)
process.once('SIGTERM', close)
