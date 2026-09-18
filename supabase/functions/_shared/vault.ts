// Vault access. Secrets are written inside `create_agent` (same transaction
// as the agent row, so no orphans) and read back only through the
// service-role RPC below — never through a table the app can query.
import type { SupabaseClient } from './deps.ts';
import { fromPostgrest } from './errors.ts';
import type { AgentStatus } from './types.ts';

/** What actions-inbound / actions-decision need about an agent. */
export interface AgentInboundContext {
  workspaceId: string;
  status: AgentStatus;
  callbackUrl: string;
  secret: string | null;
}

/** Loads an agent's workspace, status, default callback and decrypted secret. */
export async function getAgentInboundContext(
  client: SupabaseClient,
  agentId: string,
): Promise<AgentInboundContext | null> {
  const { data, error } = await client
    .rpc('get_agent_inbound_context', { p_agent_id: agentId })
    .maybeSingle<{
      workspace_id: string;
      status: AgentStatus;
      callback_url: string;
      secret: string | null;
    }>();
  if (error) throw fromPostgrest(error);
  if (!data) return null;
  return {
    workspaceId: data.workspace_id,
    status: data.status,
    callbackUrl: data.callback_url,
    secret: data.secret,
  };
}
