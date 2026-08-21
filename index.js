import { createToolDefinitions, KaleidoSphereRuntime } from './lib/runtime.mjs'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'kaleidosphere-dsh-plugin'
export const inject = ['tools']

/**
 * Mount the KaleidoSphere runtime and six native DSH tools in this Loader
 * fiber. Tool registrations belong to the fiber; the runtime effect owns its
 * temporary analysis profile and in-memory receipt/discovery state.
 *
 * @param {import('@deepseek-ai/cordis').Context} ctx DSH plugin context.
 * @param {unknown} config Bundle configuration.
 * @returns {Promise<void>}
 */
export async function apply(ctx, config = {}) {
  await ctx.effect(async () => {
    const runtime = await KaleidoSphereRuntime.create(config)
    for (const definition of createToolDefinitions(runtime)) ctx.tools.register(defineTool(definition))
    return async () => runtime.dispose()
  }, 'kaleidosphere-dsh-plugin: runtime and native tools')
}
