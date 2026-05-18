export { IPC_VALIDATOR } from "./validator.js";

// MCP server (shared by claude-code and codex adapters)
export {
  startServer,
  WIRE_IPC_TOOLS,
  handleWireIpcToolCall,
  type WireIpcDeps,
  type ToolCallResult,
} from "./mcp-server.js";
