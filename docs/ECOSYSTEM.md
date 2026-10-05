# One Pebble ecosystem, three useful tools

[Open the ecosystem home](https://pebble-peach-kappa.vercel.app/?view=ecosystem). The home brings real model generation and safe guard simulation into the language studio. Each product also remains a standalone app, with a shared product switcher and direct handoffs.

| Product | A practical use | What runs | Boundary |
|---|---|---|---|
| [Pebble](https://pebble-peach-kappa.vercel.app/?view=studio) | Learn functions, debug an algorithm, transform JSON, inspect execution | Browser interpreter and worker; optional desktop tensor/ML runtime | Training requires the local runtime, not the browser editor |
| [PebbleLM](https://pebble-llm.vercel.app/) | Explore training, sampling, memorization and different question phrasings | The released exactly 2,000,000-parameter character Transformer, trained in Pebble | Educational model on a small corpus, not a general assistant or code generator |
| [Sentinel](https://pebble-sentinel.vercel.app/) | Approve agent tool calls, review typed effects and inspect audit trails | A separate 1,288,368-parameter PAL Transformer plus explicit rules | Hosted laboratory simulates; real protection requires a local adapter and tool isolation |

## Start with a question, finish with something observable

1. **Learn a concept:** ask PebbleLM about functions, then open a known functions example in the language studio. Change a value, run it and inspect the trace. The generated text is an explanation; it is never executed as code.
2. **Understand a model:** inspect the parameter-count calculation and reports in PebbleLM, then read the Pebble ML guide and run the released local training programs. The browser cannot train these models. Check reserved-prompt results rather than assuming memorized answers generalize.
3. **Inspect an agent boundary:** replay normal project work and a reviewed suspicious chain in the embedded Sentinel panel, then open the full guard laboratory for modes, typed-action composition and audit review. To protect your own agent, integrate the local harness, Hermes hooks or MCP gate.

Use-case journeys and product links preselect approved examples/scenarios. They do not automatically execute a program, generate a model answer or change a real guard's mode. Existing Studio projects remain saved on the same browser origin.

## Integration

The ecosystem home uses same-origin `/api/ecosystem/llm/generate` and `/api/ecosystem/sentinel/*` routes. Vercel forwards them to the existing fixed production services; the local Vite preview uses the same fixed-host proxies. There is no arbitrary URL proxy, API key or new third-party model service. Standalone model inference stays on PebbleLM; standalone guard scoring stays on Sentinel. Loading/error states allow visitors to open the original product if a service is unavailable.

Each public app publishes `ecosystem.json` with canonical product links and scope. Original source, model weights and authored data remain MIT. Third-party dependencies retain their own licenses.

## Evidence stays attached to the product

PebbleLM's reserved-prompt exact-answer score is 4/40; its canonical seen-prompt score is 38/40. This is not a measure of general intelligence. Sentinel's rules already detect all six authored attack episodes, its false alarms remain material, and mature-window scorer p95 is 48.387 ms. The integrated UI uses the actual services; combining the apps does not improve these published model results.

## Motion and direct journeys

Scroll reveals, layered 3D illustrations and pointer responses add depth without moving editable code or automatically running work. Motion respects the operating-system preference and each app offers a visible reduced-motion control. The illustrations explain architecture; they are not live training or security telemetry.

Share a selected embedded tool with `?view=ecosystem&tool=language`, `tool=model` or `tool=sentinel`. Refresh and back navigation retain the approved selection; generation and replay still require an explicit action. [PebbleLM’s usage guide](https://pebble-llm.vercel.app/guide.html) includes the recorded showcase alongside local training instructions.
