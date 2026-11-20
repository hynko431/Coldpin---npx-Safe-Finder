                                                      
import { JSONRPC_ERRORS,                                                           } from "./types.mjs";

export const MAX_STDIO_FRAME_BYTES = 1_048_576; // 1 MiB hard line limit

                                        
                   
                    
                         
                               
                         
                                                           
                                           
                       
 

/**
 * Zero-dependency byte-buffered JSON-RPC 2.0 stdio transport:
 * - Scans raw Buffer bytes for `0x0a` (`\n`) before UTF-8 decoding (multi-byte safe).
 * - Trims trailing `0x0d` (`\r`) for Windows CRLF clients.
 * - Caps frames at 1 MiB and recovers cleanly with `-32700` Parse Error without crashing.
 * - Guards `process.stdout` and `console.*` so stray logs can never corrupt JSON-RPC framing.
 * - Honors Writable stream backpressure (`write() === false` -> awaits `drain`).
 */
export class StdioJsonRpcTransport {
                   input          ;
                   output          ;
                   errorOutput          ;
                   maxFrameBytes        ;
                   rawWrite                            ;
                   onMessage                                               ;
                   onParseError                            ;
                   onClose             ;

          buffer         = Buffer.alloc(0);
          discardingOversizedLine = false;
          writeChain                = Promise.resolve();
          closed = false;
          nextClientReqId = 1;
                   pendingClientRequests = new Map 
           
     
                                      
                                   
                                           
     
   ();

  constructor(opts                       ) {
    this.input = opts.input ?? process.stdin;
    this.output = opts.output ?? process.stdout;
    this.errorOutput = opts.errorOutput ?? process.stderr;
    this.maxFrameBytes = opts.maxFrameBytes ?? MAX_STDIO_FRAME_BYTES;
    this.onMessage = opts.onMessage;
    this.onParseError = opts.onParseError;
    this.onClose = opts.onClose;

    // Bind original write method BEFORE installing any stdout hijack guard
    const boundOut = this.output.write.bind(this.output);
    this.rawWrite = (chunk        ) => boundOut(chunk, "utf8");

    if (opts.hijackProcessStdio && this.output === process.stdout) {
      this.installStdoutHijackGuard();
    }
  }

          installStdoutHijackGuard()       {
    const errOut = this.errorOutput;
    const redirectToStderr = (...args           )       => {
      const text = args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ");
      errOut.write(`${text}\n`);
    };
    console.log = redirectToStderr;
    console.info = redirectToStderr;
    console.debug = redirectToStderr;
    console.warn = redirectToStderr;
    console.error = redirectToStderr;

    // Redirect any accidental direct process.stdout.write() from third-party/stray paths to stderr
    process.stdout.write = ((chunk                     , ...rest           )          => {
      const cb = typeof rest[rest.length - 1] === "function" ? (rest[rest.length - 1]              ) : undefined;
      const ok = errOut.write(chunk);
      if (cb) cb();
      return ok;
    })                               ;
  }

  start()       {
    this.input.on("data", (chunk                 ) => {
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

          flushTrailingAndClose()       {
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

          handleChunk(chunk        )       {
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

          emitFrameParseError(message        )       {
    if (this.onParseError) this.onParseError(message);
    void this.sendError(null, JSONRPC_ERRORS.PARSE_ERROR, message);
  }

          dispatchLine(lineBuf        )       {
    const lineStr = lineBuf.toString("utf8").trim();
    if (!lineStr) return;
    let parsed         ;
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
      const resp = parsed                   ;
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

  send(payload                                  )                {
    if (this.closed) return Promise.resolve();
    const serialized = `${JSON.stringify(payload)}\n`;
    this.writeChain = this.writeChain.then(
      () =>
        new Promise      ((resolveWrite) => {
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

  sendResult(id           , result         )                {
    return this.send({ jsonrpc: "2.0", id, result });
  }

  sendError(id           , code        , message        , data          )                {
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

  sendClientRequest(method        , params                          , timeoutMs = 3000)                   {
    if (this.closed) return Promise.reject(new Error("Transport closed"));
    const id = `coldpin_srv_${this.nextClientReqId++}`;
    return new Promise         ((resolveReq, rejectReq) => {
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

  writeStderrLog(event                         )       {
    const line = `${JSON.stringify({
      ts_utc: new Date().toISOString(),
      stream: "operational",
      ...event,
    })}\n`;
    this.errorOutput.write(line);
  }

  async flush()                {
    await this.writeChain;
  }
}


//# sourceURL=mcp/stdio-transport.ts
