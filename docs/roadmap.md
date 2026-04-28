# Roadmap

## Phase 0: Working Scanner Skeleton ✓

- text + JSON output
- SARIF output and GitHub Actions example
- built-in rulepack
- harness guardrail heuristics
- repo-local config file
- config suppressions and generated baselines
- `init` command for config, workflow, and baseline scaffolding
- ROS control-plane heuristics
- scenario affordance heuristics
- sample unsafe fixture

## Phase 1: Embodied-System Depth (in progress)

- [x] actuator capability inventory via `hardcoded-robot-endpoint` pattern rule
- [x] network-exposed robot control endpoint discovery (`hardcoded-robot-endpoint`, rosbridge scanner)
- [x] eval/exec injection and insecure deserialization rules
- [ ] ROS topic / service / action graph inspection (structured graph, not heuristic)
- [ ] clearer sim-vs-real interface tracing with explicit deployment-mode tagging

## Phase 2: Scene and Workflow Semantics (in progress)

- [x] prompt-injection-to-physical-action tracing (`PromptInjectionScanner`: `llm-input-to-shell`, `unvalidated-tool-call-forwarding`)
- [ ] structured scene manifest schema
- [ ] business-workflow risk scoring
- [ ] multi-agent escalation and conflict analysis

## Phase 3: Deployment Integration (in progress)

- [x] GitHub Action (`action.yml`) — use with `uses: longbiaochen/lily-sweep@v0`
- [x] suppression file for accepted risks (baseline + per-file suppressions)
- [ ] policy baselines per environment (dev / staging / production profiles)
- [ ] signed scan report for deployment gates

