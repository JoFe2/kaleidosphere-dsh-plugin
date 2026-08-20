export const PLANNING_POLICY_VERSION = 'chimpmaera.bi/planning-policy/v1';

export const SAMPLING_PROFILES = Object.freeze({
  deterministic_extract_v1: Object.freeze({ temperature: 0.0, topP: 0.9, seed: 7, maxTokens: 512 }),
  precise_tool_v1: Object.freeze({ temperature: 0.1, topP: 0.9, seed: 7, maxTokens: 768 }),
  balanced_analysis_v1: Object.freeze({ temperature: 0.2, topP: 0.95, seed: 7, maxTokens: 1024 }),
  deep_hypothesis_v1: Object.freeze({ temperature: 0.4, topP: 0.95, seed: 7, maxTokens: 1024 }),
  preview_design_v1: Object.freeze({ temperature: 0.6, topP: 0.95, seed: 7, maxTokens: 1024 }),
  preview_design_high_v1: Object.freeze({ temperature: 0.8, topP: 0.95, seed: 7, maxTokens: 1024 }),
  critique_repair_v1: Object.freeze({ temperature: 0.1, topP: 0.9, seed: 7, maxTokens: 768 }),
});

const TEMPERATURE_COMPARATORS = Object.freeze({
  extraction: 0.1,
  sql: 0.0,
  anomaly_quality: 0.4,
  relationship_cause: 0.2,
  synthesis: 0.4,
  visualization: 0.4,
  repair: 0.2,
  persistent_apply: 0.0,
});

const CLASS_RULES = Object.freeze({
  extraction: { pattern: 'direct-execute-check', sampling: 'deterministic_extract_v1', validationDepth: 'exact', toolBudget: 4, stepBudget: 6 },
  sql: { pattern: 'plan-execute-check', sampling: 'precise_tool_v1', validationDepth: 'exact-and-bounded', toolBudget: 6, stepBudget: 8 },
  anomaly_quality: { pattern: 'hypothesis-test-revise', sampling: 'balanced_analysis_v1', validationDepth: 'oracle-and-citations', toolBudget: 12, stepBudget: 16 },
  relationship_cause: { pattern: 'hierarchical-decomposition', sampling: 'deep_hypothesis_v1', validationDepth: 'graph-targeted-tests', toolBudget: 16, stepBudget: 20 },
  synthesis: { pattern: 'plan-synthesize-self-check', sampling: 'balanced_analysis_v1', validationDepth: 'citation-and-overreach', toolBudget: 4, stepBudget: 8 },
  visualization: { pattern: 'preview-compare-critique', sampling: 'preview_design_v1', validationDepth: 'truth-ux-decision', toolBudget: 0, stepBudget: 8 },
  repair: { pattern: 'diagnose-repair-replay', sampling: 'critique_repair_v1', validationDepth: 'full-regression', toolBudget: 8, stepBudget: 12 },
  persistent_apply: { pattern: 'clarify-preview-approve-apply-readback', sampling: 'precise_tool_v1', validationDepth: 'approval-readback-rollback', toolBudget: 4, stepBudget: 10 },
});

export function classifyTask(objective) {
  const text = String(objective ?? '').toLowerCase();
  if (/delete|drop|publish|apply|persist/.test(text)) return 'persistent_apply';
  if (/dashboard|visual|chart|layout/.test(text)) return 'visualization';
  if (/root.?cause|relationship|driver|correlat/.test(text)) return 'relationship_cause';
  if (/anomal|quality|defect|outlier|missing|duplicate/.test(text)) return 'anomaly_quality';
  if (/sql|query|filter/.test(text)) return 'sql';
  if (/repair|correct|retry|critique/.test(text)) return 'repair';
  if (/summary|recommend|executive|synthesi/.test(text)) return 'synthesis';
  return 'extraction';
}

export function selectPlanningPolicy(objective, { underspecified = false, adversarial = false } = {}) {
  const taskClass = classifyTask(objective);
  const rule = CLASS_RULES[taskClass];
  return {
    schemaVersion: PLANNING_POLICY_VERSION,
    taskClass,
    ...rule,
    samplingProfile: { id: rule.sampling, ...SAMPLING_PROFILES[rule.sampling] },
    clarification: underspecified ? 'required-before-targeted-analysis' : 'only-on-material-ambiguity',
    escalation: adversarial || taskClass === 'persistent_apply' ? 'trusted-user-boundary' : 'fail-closed-on-capability-gap',
    fallback: 'retain-incumbent-and-return-evidence-bound-partial',
    reconciliation: 'idempotency-key-plus-readback',
    persistentActionAllowed: false,
  };
}

export function planningPolicyGuide() {
  const guide = Object.fromEntries(Object.entries(CLASS_RULES).map(([taskClass, rule]) => [taskClass, {
    ...rule, samplingProfile: { id: rule.sampling, ...SAMPLING_PROFILES[rule.sampling] },
    clarification: taskClass === 'persistent_apply' ? 'mandatory' : 'material-ambiguity-only',
    escalation: taskClass === 'persistent_apply' ? 'trusted-approval-required' : 'capability-gap',
    fallback: 'incumbent', reconciliation: 'idempotency-and-readback',
  }]));
  guide.visualization.previewOnlyHighTemperatureComparator = { id: 'preview_design_high_v1', ...SAMPLING_PROFILES.preview_design_high_v1 };
  return guide;
}

export function planningComparisonMatrix() {
  return Object.entries(CLASS_RULES).map(([taskClass, rule]) => {
    const incumbent = SAMPLING_PROFILES[rule.sampling];
    return {
      taskClass,
      planningPattern: rule.pattern,
      validationDepth: rule.validationDepth,
      toolBudget: rule.toolBudget,
      stepBudget: rule.stepBudget,
      pairedInputRule: 'same-objective-evidence-tools-prompt-and-validator',
      changedFactor: 'temperature-only',
      incumbent: { profileId: rule.sampling, ...incumbent },
      comparator: { profileId: `${rule.sampling}:temperature-comparator`, ...incumbent, temperature: TEMPERATURE_COMPARATORS[taskClass] },
      promotionRule: 'screening-only; no promotion without zero-hard-failure paired holdout evidence',
    };
  });
}
