import type { Readable, Writable } from "node:stream";
import { JSONRPC_ERRORS, type JsonRpcId, type JsonRpcRequest, type JsonRpcResponse } from "./types.ts";

export const MAX_STDIO_FRAME_BYTES = 1_048_576; // 1 MiB hard line limit

export interface StdioTransportOptions {
  input?: Readable;
  output?: Writable;
  errorOutput?: Writable;
  hijackProcessStdio?: boolean;
  maxFrameBytes?: number;
  onMessage: (rawMessage: unknown) => Promise<void> | void;
  onParseError?: (message: string) => void;
  onClose?: () => void;
}

/**
 * Zero-dependency byte-buffered JSON-RPC 2.0 stdio transport:
 * - Scans raw Buffer bytes for `0x0a` (`\n`) before UTF-8 decoding (multi-byte safe).
 * - Trims trailing `0x0d` (`\r`) for Windows CRLF clients.
 * - Caps frames at 1 MiB and recovers cleanly with `-32700` Parse Error without crashing.
 * - Guards `process.stdout` and `console.*` so stray logs can never corrupt JSON-RPC framing.
 * - Honors Writable stream backpressure (`write() === false` -> awaits `drain`).
 */
export class StdioJsonRpcTransport {
  private readonly input: Readable;
  private readonly output: Writable;
  private readonly errorOutput: Writable;
  private readonly maxFrameBytes: number;
  private readonly rawWrite: (chunk: string) => boolean;
  private readonly onMessage: (rawMessage: unknown) => Promise<void> | void;
  private readonly onParseError?: (message: string) => void;
  private readonly onClose?: () => void;

  private buffer: Buffer = Buffer.alloc(0);
  private discardingOversizedLine = false;
  private writeChain: Promise<void> = Promise.resolve();
  private closed = false;
  private nextClientReqId = 1;
  private readonly pendingClientRequests = new Map<
    string,
    {
      resolve: (val: unknown) => void;
      reject: (err: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();

  constructor(opts: StdioTransportOptions) {
    this.input = opts.input ?? process.stdin;
    this.output = opts.output ?? process.stdout;
    this.errorOutput = opts.errorOutput ?? process.stderr;
    this.maxFrameBytes = opts.maxFrameBytes ?? MAX_STDIO_FRAME_BYTES;
    this.onMessage = opts.onMessage;
    this.onParseError = opts.onParseError;
    this.onClose = opts.onClose;

    // Bind original write method BEFORE installing any stdout hijack guard
    const boundOut = this.output.write.bind(this.output);
    this.rawWrite = (chunk: string) => boundOut(chunk, "utf8");

    if (opts.hijackProcessStdio && this.output === process.stdout) {
      this.installStdoutHijackGuard();
    }
  }

  private installStdoutHijackGuard(): void {
    const errOut = this.errorOutput;
    const redirectToStderr = (...args: unknown[]): void => {
      const text = args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ");
      errOut.write(`${text}\n`);
    };
    console.log = redirectToStderr;
    console.info = redirectToStderr;
    console.debug = redirectToStderr;
    console.warn = redirectToStderr;
    console.error = redirectToStderr;

    // Redirect any accidental direct process.stdout.write() from third-party/stray paths to stderr
    process.stdout.write = ((chunk: string | Uint8Array, ...rest: unknown[]): boolean => {
      const cb = typeof rest[rest.length - 1] === "function" ? (rest[rest.length - 1] as () => void) : undefined;
      const ok = errOut.write(chunk);
      if (cb) cb();
      return ok;
    }) as typeof process.stdout.write;
  }

  start(): void {
    this.input.on("data", (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      this.handleChunk(buf);
    });
    this.input.on("end", () => {
      this.flushTrailingAndClose();
    });
    this.input.on("close", () => {
      this.flushTrailingAndClose();
    });
  }

  private flushTrailingAndClose(): void {
    if (this.closed) return;
    if (!this.discardingOversizedLine && this.buffer.byteLength > 0) {
      const lineBuf =
        this.buffer[this.buffer.byteLength - 1] === 0x0d
          ? this.buffer.subarray(0, this.buffer.byteLength - 1)
          : this.buffer;
      this.buffer = Buffer.alloc(0);
      if (lineBuf.byteLength > 0) {
        this.dispatchLine(lineBuf);
      }
    }
    this.closed = true;
    for (const [id, pending] of this.pendingClientRequests) {
      clearTimeout(pending.timer);
      pending.reject(new Error("Transport closed"));
      this.pendingClientRequests.delete(id);
    }
    if (this.onClose) this.onClose();
  }

  private handleChunk(chunk: Buffer): void {
    if (this.closed || chunk.byteLength === 0) return;

    let offset = 0;
    while (offset < chunk.byteLength) {
      if (this.discardingOversizedLine) {
        const nlIdx = chunk.indexOf(0x0a, offset);
        if (nlIdx === -1) {
          return;
        }
        this.discardingOversizedLine = false;
        offset = nlIdx + 1;
        continue;
      }

      const nlIdx = chunk.indexOf(0x0a, offset);
      if (nlIdx === -1) {
        const remaining = chunk.subarray(offset);
        if (this.buffer.byteLength + remaining.byteLength > this.maxFrameBytes) {
          this.buffer = Buffer.alloc(0);
          this.discardingOversizedLine = true;
          this.emitFrameParseError(`Message frame exceeded maximum size (${this.maxFrameBytes} bytes).`);
          return;
        }
        this.buffer = this.buffer.byteLength === 0 ? Buffer.from(remaining) : Buffer.concat([this.buffer, remaining]);
        return;
      }

      const piece = chunk.subarray(offset, nlIdx);
      offset = nlIdx + 1;

      if (this.buffer.byteLength + piece.byteLength > this.maxFrameBytes) {
        this.buffer = Buffer.alloc(0);
        this.emitFrameParseError(`Message frame exceeded maximum size (${this.maxFrameBytes} bytes).`);
        continue;
      }

      const fullLine = this.buffer.byteLength === 0 ? piece : Buffer.concat([this.buffer, piece]);
      this.buffer = Buffer.alloc(0);

      const trimmed =
        fullLine.byteLength > 0 && fullLine[fullLine.byteLength - 1] === 0x0d
          ? fullLine.subarray(0, fullLine.byteLength - 1)
          : fullLine;
      if (trimmed.byteLength === 0) continue;

      this.dispatchLine(trimmed);
    }
  }

  private emitFrameParseError(message: string): void {
    if (this.onParseError) this.onParseError(message);
    void this.sendError(null, JSONRPC_ERRORS.PARSE_ERROR, message);
  }

  private dispatchLine(lineBuf: Buffer): void {
    const lineStr = lineBuf.toString("utf8").trim();
    if (!lineStr) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(lineStr);
    } catch {
      this.emitFrameParseError("Malformed JSON-RPC message.");
      return;
    }

    // Intercept responses to server-initiated requests (such as `roots/list`)
    if (
      parsed !== null &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      !("method" in parsed) &&
      "id" in parsed
    ) {
      const resp = parsed as JsonRpcResponse;
      const key = String(resp.id);
      const pending = this.pendingClientRequests.get(key);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingClientRequests.delete(key);
        if (resp.error) {
          pending.reject(new Error(resp.error.message || "Client request failed"));
        } else {
          pending.resolve(resp.result);
        }
        return;
      }
    }

    Promise.resolve(this.onMessage(parsed)).catch((err) => {
      this.writeStderrLog({
        stage: "transport_dispatch_error",
        error: err instanceof Error ? err.message : String(err),
      });
    });
  }

  send(payload: JsonRpcResponse | JsonRpcRequest): Promise<void> {
    if (this.closed) return Promise.resolve();
    const serialized = `${JSON.stringify(payload)}\n`;
    this.writeChain = this.writeChain.then(
      () =>
        new Promise<void>((resolveWrite) => {
          if (this.closed) {
            resolveWrite();
            return;
          }
          const ok = this.rawWrite(serialized);
          if (ok) {
            resolveWrite();
          } else {
            this.output.once("drain", () => resolveWrite());
          }
        }),
    );
    return this.writeChain;
  }

  sendResult(id: JsonRpcId, result: unknown): Promise<void> {
    return this.send({ jsonrpc: "2.0", id, result });
  }

  sendError(id: JsonRpcId, code: number, message: string, data?: unknown): Promise<void> {
    return this.send({
      jsonrpc: "2.0",
      id,
      error: {
        code,
        message,
        ...(data !== undefined ? { data } : {}),
      },
    });
  }

  sendClientRequest(method: string, params?: Record<string, unknown>, timeoutMs = 3000): Promise<unknown> {
    if (this.closed) return Promise.reject(new Error("Transport closed"));
    const id = `coldpin_srv_${this.nextClientReqId++}`;
    return new Promise<unknown>((resolveReq, rejectReq) => {
      const timer = setTimeout(() => {
        this.pendingClientRequests.delete(id);
        rejectReq(new Error(`Client request '${method}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.pendingClientRequests.set(id, { resolve: resolveReq, reject: rejectReq, timer });
      void this.send({
        jsonrpc: "2.0",
        id,
        method,
        ...(params ? { params } : {}),
      });
    });
  }

  writeStderrLog(event: Record<string, unknown>): void {
    const line = `${JSON.stringify({
      ts_utc: new Date().toISOString(),
      stream: "operational",
      ...event,
    })}\n`;
    this.errorOutput.write(line);
  }

  async flush(): Promise<void> {
    await this.writeChain;
  }
}
