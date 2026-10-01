import { NextRequest, NextResponse } from 'next/server'
import { internalKeyHeaders } from '@/lib/agentAuth'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'
import { isChatProvider } from '@/lib/llmProviderPresets'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// POST /api/models { userId? } - Fetch available AI models from all configured providers.
// Body-based (not query-string) so plaintext apiKey values never appear in access logs.
export async function POST(request: NextRequest) {
  try {
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff

    const { userId } = await request.json().catch(() => ({ userId: null }))

    // Only ever load the EFFECTIVE user's providers; the body userId cannot be
    // used to enumerate another user's configured providers.
    let providers: unknown[] = []
    if (userId) {
      const rows = await prisma.userLlmProvider.findMany({ where: { userId: eff.userId } })
      // A non-chat key (Jev) lists no models, so it never leaves the webapp here.
      providers = rows.filter(isChatProvider)
    }

    const res = await fetch(`${AGENT_API_URL}/models`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ providers: providers.length > 0 ? providers : null }),
      cache: 'no-store',
    })

    if (!res.ok) {
      console.error('Failed to fetch models from agent API:', await res.text())
      return NextResponse.json(
        { error: 'Failed to fetch models from agent API' },
        { status: 503 }
      )
    }

    const data = await res.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Failed to connect to agent API for models:', error)
    return NextResponse.json(
      { error: 'Failed to connect to agent API' },
      { status: 503 }
    )
  }
}
